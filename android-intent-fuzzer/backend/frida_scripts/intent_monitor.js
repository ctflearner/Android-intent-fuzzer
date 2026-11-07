/**
 * intent_monitor.js -- Track all Intent-based IPC calls.
 *
 * Hooks:
 *   - Activity.startActivity / startActivityForResult
 *   - Context.sendBroadcast / sendOrderedBroadcast / sendStickyBroadcast
 *   - Context.startService / startForegroundService
 *   - ContentResolver.query / insert / update / delete
 *   - PendingIntent creation
 *
 * Usage: frida -U -l intent_monitor.js -f <package> --no-pause
 */

'use strict';

(function () {
    var intentLog = [];

    rpc.exports = {
        getLog: function () {
            return intentLog;
        },
        reset: function () {
            intentLog = [];
        },
        getStats: function () {
            var stats = { activities: 0, broadcasts: 0, services: 0, providers: 0, total: intentLog.length };
            for (var i = 0; i < intentLog.length; i++) {
                var cat = intentLog[i].category;
                if (cat === 'activity') stats.activities++;
                else if (cat === 'broadcast') stats.broadcasts++;
                else if (cat === 'service') stats.services++;
                else if (cat === 'provider') stats.providers++;
            }
            return stats;
        }
    };

    function extractIntentInfo(intent) {
        if (!intent) return { action: null, component: null, data: null, categories: [], extras: null, flags: 0 };
        var info = {};
        try { info.action = intent.getAction(); } catch (e) { info.action = null; }
        try {
            var comp = intent.getComponent();
            info.component = comp ? comp.flattenToString() : null;
        } catch (e) { info.component = null; }
        try {
            var data = intent.getData();
            info.data = data ? data.toString() : null;
        } catch (e) { info.data = null; }
        try { info.type = intent.getType(); } catch (e) { info.type = null; }
        try { info.flags = intent.getFlags(); } catch (e) { info.flags = 0; }
        try {
            var cats = intent.getCategories();
            info.categories = [];
            if (cats) {
                var iter = cats.iterator();
                while (iter.hasNext()) {
                    info.categories.push(iter.next().toString());
                }
            }
        } catch (e) { info.categories = []; }
        try {
            var extras = intent.getExtras();
            if (extras) {
                info.extras = {};
                var keys = extras.keySet().iterator();
                while (keys.hasNext()) {
                    var key = keys.next().toString();
                    try {
                        var val = extras.get(key);
                        info.extras[key] = val ? val.toString() : null;
                    } catch (e2) {
                        info.extras[key] = '<unreadable>';
                    }
                }
            } else {
                info.extras = null;
            }
        } catch (e) { info.extras = null; }
        return info;
    }

    Java.perform(function () {
        send({ type: 'intent_monitor', status: 'starting' });

        // --- startActivity ---
        try {
            var Activity = Java.use('android.app.Activity');

            Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'activity',
                    method: 'startActivity',
                    intent: info,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.startActivity(intent);
            };

            Activity.startActivityForResult.overload('android.content.Intent', 'int').implementation = function (intent, requestCode) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'activity',
                    method: 'startActivityForResult',
                    intent: info,
                    request_code: requestCode,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.startActivityForResult(intent, requestCode);
            };
            send({ type: 'intent_monitor', hook: 'Activity', status: 'hooked' });
        } catch (e) {
            send({ type: 'intent_monitor', hook: 'Activity', status: 'failed', error: e.toString() });
        }

        // --- sendBroadcast ---
        try {
            var ContextWrapper = Java.use('android.content.ContextWrapper');

            ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'broadcast',
                    method: 'sendBroadcast',
                    intent: info,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.sendBroadcast(intent);
            };

            ContextWrapper.sendBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent, permission) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'broadcast',
                    method: 'sendBroadcast',
                    intent: info,
                    required_permission: permission,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.sendBroadcast(intent, permission);
            };

            ContextWrapper.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String').implementation = function (intent, permission) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'broadcast',
                    method: 'sendOrderedBroadcast',
                    intent: info,
                    required_permission: permission,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.sendOrderedBroadcast(intent, permission);
            };
            send({ type: 'intent_monitor', hook: 'Broadcast', status: 'hooked' });
        } catch (e) {
            send({ type: 'intent_monitor', hook: 'Broadcast', status: 'failed', error: e.toString() });
        }

        // --- startService ---
        try {
            var ContextWrapper = Java.use('android.content.ContextWrapper');

            ContextWrapper.startService.overload('android.content.Intent').implementation = function (intent) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'service',
                    method: 'startService',
                    intent: info,
                    caller: this.getClass().getName(),
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.startService(intent);
            };

            try {
                ContextWrapper.startForegroundService.overload('android.content.Intent').implementation = function (intent) {
                    var info = extractIntentInfo(intent);
                    var entry = {
                        type: 'intent_monitor',
                        category: 'service',
                        method: 'startForegroundService',
                        intent: info,
                        caller: this.getClass().getName(),
                        timestamp: Date.now()
                    };
                    intentLog.push(entry);
                    send(entry);
                    return this.startForegroundService(intent);
                };
            } catch (e2) { /* API < 26 */ }

            send({ type: 'intent_monitor', hook: 'Service', status: 'hooked' });
        } catch (e) {
            send({ type: 'intent_monitor', hook: 'Service', status: 'failed', error: e.toString() });
        }

        // --- ContentResolver ---
        try {
            var ContentResolver = Java.use('android.content.ContentResolver');

            ContentResolver.query.overload(
                'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'
            ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
                var entry = {
                    type: 'intent_monitor',
                    category: 'provider',
                    method: 'ContentResolver.query',
                    uri: uri ? uri.toString() : null,
                    selection: selection,
                    caller: 'ContentResolver',
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            };

            ContentResolver.insert.overload('android.net.Uri', 'android.content.ContentValues').implementation = function (uri, values) {
                var entry = {
                    type: 'intent_monitor',
                    category: 'provider',
                    method: 'ContentResolver.insert',
                    uri: uri ? uri.toString() : null,
                    caller: 'ContentResolver',
                    timestamp: Date.now()
                };
                intentLog.push(entry);
                send(entry);
                return this.insert(uri, values);
            };
            send({ type: 'intent_monitor', hook: 'ContentResolver', status: 'hooked' });
        } catch (e) {
            send({ type: 'intent_monitor', hook: 'ContentResolver', status: 'failed', error: e.toString() });
        }

        // --- PendingIntent ---
        try {
            var PendingIntent = Java.use('android.app.PendingIntent');

            PendingIntent.getActivity.overload(
                'android.content.Context', 'int', 'android.content.Intent', 'int'
            ).implementation = function (context, requestCode, intent, flags) {
                var info = extractIntentInfo(intent);
                var entry = {
                    type: 'intent_monitor',
                    category: 'activity',
                    method: 'PendingIntent.getActivity',
                    intent: info,
                    flags: flags,
                    timestamp: Date.now()
                };

                // Flag mutable PendingIntents (security risk on API >= 31)
                if ((flags & 0x02000000) === 0) { // FLAG_MUTABLE = 0x02000000
                    entry.risk = 'medium';
                    entry.note = 'Mutable PendingIntent -- potential intent hijack';
                }

                intentLog.push(entry);
                send(entry);
                return PendingIntent.getActivity(context, requestCode, intent, flags);
            };
            send({ type: 'intent_monitor', hook: 'PendingIntent', status: 'hooked' });
        } catch (e) {
            send({ type: 'intent_monitor', hook: 'PendingIntent', status: 'failed', error: e.toString() });
        }

        send({ type: 'intent_monitor', status: 'complete' });
    });
})();
