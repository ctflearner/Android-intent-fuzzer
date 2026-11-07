/**
 * root_bypass.js -- Root detection bypass.
 *
 * Hooks common root-detection techniques:
 *   - File.exists() for su, Magisk, Superuser paths
 *   - Runtime.exec() for 'which su', 'id' commands
 *   - Build.TAGS check for 'test-keys'
 *   - System property checks (ro.debuggable, ro.secure)
 *   - PackageManager queries for root apps
 *   - Native fopen/access calls for root indicators
 *
 * Usage: frida -U -l root_bypass.js -f <package> --no-pause
 */

'use strict';

(function () {
    var ROOT_PATHS = [
        '/system/app/Superuser.apk',
        '/system/xbin/su',
        '/system/bin/su',
        '/sbin/su',
        '/data/local/xbin/su',
        '/data/local/bin/su',
        '/data/local/su',
        '/su/bin/su',
        '/system/bin/.ext/.su',
        '/system/usr/we-need-root/su-backup',
        '/system/xbin/mu',
        '/system/app/Superuser',
        '/system/etc/init.d/99telecominfra',
        '/magisk',
        '/sbin/.magisk',
        '/data/adb/magisk',
        '/cache/.disable_magisk',
        '/dev/.magisk.unblock',
        '/system/xbin/daemonsu',
        '/system/bin/failsafe/su',
    ];

    var ROOT_PACKAGES = [
        'com.topjohnwu.magisk',
        'eu.chainfire.supersu',
        'com.koushikdutta.superuser',
        'com.noshufou.android.su',
        'com.thirdparty.superuser',
        'com.yellowes.su',
        'com.devadvance.rootcloak',
        'de.robv.android.xposed.installer',
        'com.saurik.substrate',
    ];

    Java.perform(function () {
        send({ type: 'root_bypass', status: 'starting' });

        // --- 1. File.exists() bypass ---
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                for (var i = 0; i < ROOT_PATHS.length; i++) {
                    if (path === ROOT_PATHS[i] || path.indexOf('/su') !== -1 || path.indexOf('magisk') !== -1) {
                        send({ type: 'root_bypass', hook: 'File.exists', path: path, action: 'blocked' });
                        return false;
                    }
                }
                return this.exists.call(this);
            };
            send({ type: 'root_bypass', hook: 'File.exists', status: 'hooked' });
        } catch (e) {
            send({ type: 'root_bypass', hook: 'File.exists', status: 'failed', error: e.toString() });
        }

        // --- 2. Runtime.exec() bypass ---
        try {
            var Runtime = Java.use('java.lang.Runtime');

            // String variant
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 || cmd.indexOf('busybox') !== -1) {
                    send({ type: 'root_bypass', hook: 'Runtime.exec', cmd: cmd, action: 'blocked' });
                    // Return a process that immediately exits with error
                    return Runtime.exec.call(this, 'echo');
                }
                return Runtime.exec.call(this, cmd);
            };

            // String[] variant
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
                var joined = cmdArray.join(' ');
                if (joined.indexOf('su') !== -1 || joined.indexOf('which') !== -1) {
                    send({ type: 'root_bypass', hook: 'Runtime.exec[]', cmd: joined, action: 'blocked' });
                    return Runtime.exec.call(this, ['echo']);
                }
                return Runtime.exec.call(this, cmdArray);
            };
            send({ type: 'root_bypass', hook: 'Runtime.exec', status: 'hooked' });
        } catch (e) {
            send({ type: 'root_bypass', hook: 'Runtime.exec', status: 'failed', error: e.toString() });
        }

        // --- 3. Build.TAGS bypass ---
        try {
            var Build = Java.use('android.os.Build');
            var originalTags = Build.TAGS.value;
            Build.TAGS.value = 'release-keys';
            send({ type: 'root_bypass', hook: 'Build.TAGS', original: originalTags, spoofed: 'release-keys' });
        } catch (e) {
            send({ type: 'root_bypass', hook: 'Build.TAGS', status: 'failed', error: e.toString() });
        }

        // --- 4. System property checks ---
        try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            var origGet = SystemProperties.get.overload('java.lang.String', 'java.lang.String');
            origGet.implementation = function (key, def) {
                if (key === 'ro.debuggable') {
                    send({ type: 'root_bypass', hook: 'SystemProperties', key: key, action: 'spoofed_to_0' });
                    return '0';
                }
                if (key === 'ro.secure') {
                    return '1';
                }
                if (key === 'ro.build.selinux') {
                    return '1';
                }
                return origGet.call(this, key, def);
            };
            send({ type: 'root_bypass', hook: 'SystemProperties', status: 'hooked' });
        } catch (e) {
            send({ type: 'root_bypass', hook: 'SystemProperties', status: 'failed', error: e.toString() });
        }

        // --- 5. PackageManager query bypass ---
        try {
            var PackageManager = Java.use('android.app.ApplicationPackageManager');
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
                for (var i = 0; i < ROOT_PACKAGES.length; i++) {
                    if (pkg === ROOT_PACKAGES[i]) {
                        send({ type: 'root_bypass', hook: 'PackageManager', pkg: pkg, action: 'blocked' });
                        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                    }
                }
                return this.getPackageInfo.call(this, pkg, flags);
            };
            send({ type: 'root_bypass', hook: 'PackageManager', status: 'hooked' });
        } catch (e) {
            send({ type: 'root_bypass', hook: 'PackageManager', status: 'failed', error: e.toString() });
        }

        send({ type: 'root_bypass', status: 'complete' });
    });

    // --- 6. Native fopen/access bypass ---
    try {
        var fopen = Module.findExportByName('libc.so', 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < ROOT_PATHS.length; i++) {
                            if (this.path === ROOT_PATHS[i]) {
                                send({ type: 'root_bypass', hook: 'native_fopen', path: this.path, action: 'blocked' });
                                retval.replace(ptr(0));
                                return;
                            }
                        }
                    }
                }
            });
        }

        var access = Module.findExportByName('libc.so', 'access');
        if (access) {
            Interceptor.attach(access, {
                onEnter: function (args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function (retval) {
                    if (this.path) {
                        for (var i = 0; i < ROOT_PATHS.length; i++) {
                            if (this.path === ROOT_PATHS[i]) {
                                send({ type: 'root_bypass', hook: 'native_access', path: this.path, action: 'blocked' });
                                retval.replace(ptr(-1));
                                return;
                            }
                        }
                    }
                }
            });
        }
        send({ type: 'root_bypass', hook: 'native', status: 'hooked' });
    } catch (e) {
        send({ type: 'root_bypass', hook: 'native', status: 'failed', error: e.toString() });
    }
})();
