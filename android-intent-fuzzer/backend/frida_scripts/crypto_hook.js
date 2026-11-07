/**
 * crypto_hook.js -- Monitor cryptographic operations.
 *
 * Hooks:
 *   - javax.crypto.Cipher.init() / doFinal()
 *   - javax.crypto.spec.SecretKeySpec (key material)
 *   - java.security.MessageDigest (hashing)
 *   - javax.crypto.Mac (HMAC)
 *   - java.security.KeyStore operations
 *   - javax.crypto.spec.IvParameterSpec (IV values)
 *
 * Usage: frida -U -l crypto_hook.js -f <package> --no-pause
 */

'use strict';

(function () {
    var cryptoOps = [];

    rpc.exports = {
        getOps: function () {
            return cryptoOps;
        },
        reset: function () {
            cryptoOps = [];
        }
    };

    function bytesToHex(bytes) {
        if (!bytes) return '';
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            hex += (b.length === 1 ? '0' : '') + b;
        }
        return hex;
    }

    function getStackTrace() {
        try {
            return Java.use('android.util.Log')
                .getStackTraceString(Java.use('java.lang.Exception').$new())
                .substring(0, 1000);
        } catch (e) {
            return '';
        }
    }

    Java.perform(function () {
        send({ type: 'crypto_hook', status: 'starting' });

        // --- Cipher.init ---
        try {
            var Cipher = Java.use('javax.crypto.Cipher');

            // init(int opmode, Key key)
            Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
                var mode = opmode === 1 ? 'ENCRYPT' : opmode === 2 ? 'DECRYPT' : 'OTHER(' + opmode + ')';
                var algo = this.getAlgorithm();
                var keyAlgo = key ? key.getAlgorithm() : 'null';
                var keyBytes = key ? bytesToHex(key.getEncoded()) : '';

                var entry = {
                    type: 'crypto_hook',
                    method: 'Cipher.init',
                    mode: mode,
                    algorithm: algo,
                    key_algorithm: keyAlgo,
                    key_hex: keyBytes,
                    key_length_bits: key && key.getEncoded() ? key.getEncoded().length * 8 : 0,
                    timestamp: Date.now()
                };

                // Flag weak algorithms
                if (algo && (algo.indexOf('DES') !== -1 || algo.indexOf('RC4') !== -1 || algo.indexOf('ECB') !== -1)) {
                    entry.risk = 'high';
                    entry.note = 'Weak cipher algorithm: ' + algo;
                }
                // Flag short keys
                if (entry.key_length_bits > 0 && entry.key_length_bits < 128) {
                    entry.risk = 'high';
                    entry.note = 'Weak key length: ' + entry.key_length_bits + ' bits';
                }

                cryptoOps.push(entry);
                send(entry);
                return this.init(opmode, key);
            };

            // init(int, Key, AlgorithmParameterSpec)
            Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
                var mode = opmode === 1 ? 'ENCRYPT' : opmode === 2 ? 'DECRYPT' : 'OTHER';
                var algo = this.getAlgorithm();
                var iv = '';
                try {
                    var IvSpec = Java.use('javax.crypto.spec.IvParameterSpec');
                    if (IvSpec.class.isInstance(params)) {
                        iv = bytesToHex(Java.cast(params, IvSpec).getIV());
                    }
                } catch (e2) { }

                var entry = {
                    type: 'crypto_hook',
                    method: 'Cipher.init',
                    mode: mode,
                    algorithm: algo,
                    key_hex: key ? bytesToHex(key.getEncoded()) : '',
                    iv_hex: iv,
                    timestamp: Date.now()
                };

                // Flag static / zero IVs
                if (iv && /^0+$/.test(iv)) {
                    entry.risk = 'high';
                    entry.note = 'Zero IV detected -- deterministic encryption';
                }

                cryptoOps.push(entry);
                send(entry);
                return this.init(opmode, key, params);
            };
            send({ type: 'crypto_hook', hook: 'Cipher.init', status: 'hooked' });
        } catch (e) {
            send({ type: 'crypto_hook', hook: 'Cipher.init', status: 'failed', error: e.toString() });
        }

        // --- Cipher.doFinal ---
        try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function (input) {
                var result = this.doFinal(input);
                send({
                    type: 'crypto_hook',
                    method: 'Cipher.doFinal',
                    algorithm: this.getAlgorithm(),
                    input_length: input ? input.length : 0,
                    output_length: result ? result.length : 0,
                    input_preview: input ? bytesToHex(input).substring(0, 64) : '',
                    output_preview: result ? bytesToHex(result).substring(0, 64) : '',
                    timestamp: Date.now()
                });
                return result;
            };
        } catch (e) { }

        // --- SecretKeySpec ---
        try {
            var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algo) {
                var entry = {
                    type: 'crypto_hook',
                    method: 'SecretKeySpec',
                    algorithm: algo,
                    key_hex: bytesToHex(keyBytes),
                    key_length_bits: keyBytes ? keyBytes.length * 8 : 0,
                    stack: getStackTrace(),
                    timestamp: Date.now()
                };

                // Flag hardcoded keys (always interesting to log)
                entry.note = 'Secret key created -- check if hardcoded';
                cryptoOps.push(entry);
                send(entry);
                return this.$init(keyBytes, algo);
            };
            send({ type: 'crypto_hook', hook: 'SecretKeySpec', status: 'hooked' });
        } catch (e) {
            send({ type: 'crypto_hook', hook: 'SecretKeySpec', status: 'failed', error: e.toString() });
        }

        // --- MessageDigest ---
        try {
            var MessageDigest = Java.use('java.security.MessageDigest');

            MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
                var entry = {
                    type: 'crypto_hook',
                    method: 'MessageDigest.getInstance',
                    algorithm: algo,
                    timestamp: Date.now()
                };

                if (algo === 'MD5' || algo === 'SHA1' || algo === 'SHA-1') {
                    entry.risk = 'medium';
                    entry.note = 'Weak hash algorithm: ' + algo;
                }

                cryptoOps.push(entry);
                send(entry);
                return this.getInstance(algo);
            };

            MessageDigest.digest.overload('[B').implementation = function (input) {
                var result = this.digest(input);
                send({
                    type: 'crypto_hook',
                    method: 'MessageDigest.digest',
                    algorithm: this.getAlgorithm(),
                    input_length: input ? input.length : 0,
                    output_hex: bytesToHex(result),
                    timestamp: Date.now()
                });
                return result;
            };
            send({ type: 'crypto_hook', hook: 'MessageDigest', status: 'hooked' });
        } catch (e) {
            send({ type: 'crypto_hook', hook: 'MessageDigest', status: 'failed', error: e.toString() });
        }

        // --- Mac (HMAC) ---
        try {
            var Mac = Java.use('javax.crypto.Mac');
            Mac.init.overload('java.security.Key').implementation = function (key) {
                var entry = {
                    type: 'crypto_hook',
                    method: 'Mac.init',
                    algorithm: this.getAlgorithm(),
                    key_hex: key ? bytesToHex(key.getEncoded()) : '',
                    timestamp: Date.now()
                };
                cryptoOps.push(entry);
                send(entry);
                return this.init(key);
            };
            send({ type: 'crypto_hook', hook: 'Mac', status: 'hooked' });
        } catch (e) {
            send({ type: 'crypto_hook', hook: 'Mac', status: 'failed', error: e.toString() });
        }

        // --- KeyStore ---
        try {
            var KeyStore = Java.use('java.security.KeyStore');
            KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (stream, password) {
                var entry = {
                    type: 'crypto_hook',
                    method: 'KeyStore.load',
                    store_type: this.getType(),
                    has_password: password !== null,
                    timestamp: Date.now()
                };
                if (password) {
                    entry.password_hint = Java.use('java.lang.String').$new(password);
                }
                cryptoOps.push(entry);
                send(entry);
                return this.load(stream, password);
            };
            send({ type: 'crypto_hook', hook: 'KeyStore', status: 'hooked' });
        } catch (e) {
            send({ type: 'crypto_hook', hook: 'KeyStore', status: 'failed', error: e.toString() });
        }

        send({ type: 'crypto_hook', status: 'complete' });
    });
})();
