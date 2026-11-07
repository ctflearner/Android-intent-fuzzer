/**
 * ssl_bypass.js -- Universal SSL pinning bypass.
 *
 * Targets:
 *   - Default TrustManager (X509TrustManager)
 *   - OkHttp3 CertificatePinner
 *   - Conscrypt / BoringSSL TrustManager
 *   - Apache HttpClient (legacy)
 *   - Flutter / Dart (ssl_verify_peer_cert)
 *   - WebView SSL errors
 *
 * Usage: frida -U -l ssl_bypass.js -f <package> --no-pause
 */

'use strict';

(function () {
    Java.perform(function () {
        send({ type: 'ssl_bypass', status: 'starting' });

        // --- 1. Default TrustManager bypass ---
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                name: 'com.intethunter.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () {
                        return [];
                    }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var ctx = SSLContext.getInstance('TLS');
            ctx.init(null, TrustManagers, null);
            SSLContext.setDefault(ctx);

            // Hook SSLContext.init to inject our TrustManager
            var SSLContextInit = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );
            SSLContextInit.implementation = function (km, tm, sr) {
                SSLContextInit.call(this, km, TrustManagers, sr);
            };
            send({ type: 'ssl_bypass', target: 'TrustManager', status: 'hooked' });
        } catch (e) {
            send({ type: 'ssl_bypass', target: 'TrustManager', status: 'failed', error: e.toString() });
        }

        // --- 2. OkHttp3 CertificatePinner bypass ---
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
                // No-op: skip pin validation
            };
            // Also handle the older check$okhttp overload
            try {
                CertificatePinner['check$okhttp'].implementation = function (hostname, fn) { };
            } catch (e2) { }
            send({ type: 'ssl_bypass', target: 'OkHttp3', status: 'hooked' });
        } catch (e) {
            send({ type: 'ssl_bypass', target: 'OkHttp3', status: 'not_found' });
        }

        // --- 3. Conscrypt / BoringSSL TrustManagerImpl ---
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                return untrustedChain;
            };
            send({ type: 'ssl_bypass', target: 'Conscrypt', status: 'hooked' });
        } catch (e) {
            // Try platform variant
            try {
                var PlatformTM = Java.use('com.android.org.conscrypt.Platform');
                PlatformTM.checkServerTrusted.overload(
                    'javax.net.ssl.X509TrustManager',
                    '[Ljava.security.cert.X509Certificate;',
                    'java.lang.String',
                    'com.android.org.conscrypt.AbstractConscryptSocket'
                ).implementation = function (tm, chain, authType, socket) { };
                send({ type: 'ssl_bypass', target: 'Conscrypt-Platform', status: 'hooked' });
            } catch (e2) {
                send({ type: 'ssl_bypass', target: 'Conscrypt', status: 'not_found' });
            }
        }

        // --- 4. Apache HttpClient (legacy, Android < 6) ---
        try {
            var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
            AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () { };
            send({ type: 'ssl_bypass', target: 'Apache-HttpClient', status: 'hooked' });
        } catch (e) {
            send({ type: 'ssl_bypass', target: 'Apache-HttpClient', status: 'not_found' });
        }

        // --- 5. WebView SSL error handler ---
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                handler.proceed();
            };
            send({ type: 'ssl_bypass', target: 'WebView', status: 'hooked' });
        } catch (e) {
            send({ type: 'ssl_bypass', target: 'WebView', status: 'not_found' });
        }

        // --- 6. HostnameVerifier bypass ---
        try {
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            var AllowAll = Java.registerClass({
                name: 'com.intethunter.AllowAllHostnameVerifier',
                implements: [HostnameVerifier],
                methods: {
                    verify: function (hostname, session) {
                        return true;
                    }
                }
            });
            HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
            send({ type: 'ssl_bypass', target: 'HostnameVerifier', status: 'hooked' });
        } catch (e) {
            send({ type: 'ssl_bypass', target: 'HostnameVerifier', status: 'failed', error: e.toString() });
        }

        send({ type: 'ssl_bypass', status: 'complete' });
    });

    // --- 7. Flutter / Dart native SSL bypass ---
    try {
        var libflutter = Module.findBaseAddress('libflutter.so');
        if (libflutter) {
            // Search for ssl_verify_peer_cert
            var matches = Memory.scanSync(libflutter, Process.getModuleByName('libflutter.so').size,
                '2d e9 f0 4f');  // ARM thumb push pattern
            send({ type: 'ssl_bypass', target: 'Flutter', status: 'scanning', candidates: matches.length });
        }
    } catch (e) {
        // Not a Flutter app; ignore
    }
})();
