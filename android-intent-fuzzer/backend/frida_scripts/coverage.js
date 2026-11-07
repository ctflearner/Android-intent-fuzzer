/**
 * coverage.js -- Method-level coverage tracking for target package.
 *
 * Usage: frida -U -l coverage.js -f <package> --no-pause
 *
 * Hooks Java method entries in the target package and reports
 * which methods have been exercised. Sends coverage data via
 * Frida messages.
 */

'use strict';

(function () {
    var targetPackage = null;
    var coveredMethods = {};
    var totalHooked = 0;
    var reportInterval = 5000; // ms

    rpc.exports = {
        init: function (pkg) {
            targetPackage = pkg;
            send({ type: 'coverage_init', package: pkg });
        },
        getReport: function () {
            var covered = Object.keys(coveredMethods).length;
            return {
                total_hooked: totalHooked,
                covered: covered,
                coverage_pct: totalHooked > 0 ? (covered / totalHooked * 100).toFixed(2) : '0.00',
                methods: coveredMethods
            };
        },
        reset: function () {
            coveredMethods = {};
            send({ type: 'coverage_reset' });
        }
    };

    function hookClassMethods(className) {
        try {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();

            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                var fullName = className + '.' + methodName;

                (function (cls, mName, fName) {
                    var overloads = cls[mName].overloads;
                    for (var j = 0; j < overloads.length; j++) {
                        totalHooked++;
                        overloads[j].implementation = function () {
                            if (!coveredMethods[fName]) {
                                coveredMethods[fName] = {
                                    first_hit: Date.now(),
                                    count: 0
                                };
                            }
                            coveredMethods[fName].count++;
                            coveredMethods[fName].last_hit = Date.now();
                            return this[mName].apply(this, arguments);
                        };
                    }
                })(clazz, methodName, fullName);
            }
        } catch (e) {
            // Class may not be loadable; skip
        }
    }

    Java.perform(function () {
        if (!targetPackage) {
            // Auto-detect from process name
            targetPackage = Java.use('android.app.ActivityThread')
                .currentApplication()
                .getApplicationContext()
                .getPackageName();
        }

        send({ type: 'coverage_start', package: targetPackage });

        // Enumerate loaded classes matching the target package
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                if (className.startsWith(targetPackage)) {
                    hookClassMethods(className);
                }
            },
            onComplete: function () {
                send({
                    type: 'coverage_hooked',
                    total_methods: totalHooked,
                    package: targetPackage
                });
            }
        });

        // Periodic reporting
        setInterval(function () {
            var covered = Object.keys(coveredMethods).length;
            send({
                type: 'coverage_update',
                total_hooked: totalHooked,
                covered: covered,
                coverage_pct: totalHooked > 0 ? (covered / totalHooked * 100).toFixed(2) : '0.00'
            });
        }, reportInterval);
    });
})();
