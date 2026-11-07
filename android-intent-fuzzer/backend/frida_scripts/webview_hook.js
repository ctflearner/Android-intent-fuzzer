/**
 * webview_hook.js -- Monitor WebView activity.
 *
 * Hooks:
 *   - WebView.loadUrl()
 *   - WebView.loadData() / loadDataWithBaseURL()
 *   - WebView.evaluateJavascript()
 *   - WebView.addJavascriptInterface()
 *   - WebSettings modifications (setJavaScriptEnabled, setAllowFileAccess, etc.)
 *
 * Usage: frida -U -l webview_hook.js -f <package> --no-pause
 */

'use strict';

(function () {
    var findings = [];

    rpc.exports = {
        getFindings: function () {
            return findings;
        },
        reset: function () {
            findings = [];
        }
    };

    Java.perform(function () {
        send({ type: 'webview_hook', status: 'starting' });

        var WebView = Java.use('android.webkit.WebView');

        // --- loadUrl ---
        try {
            WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
                var entry = {
                    type: 'webview_hook',
                    method: 'loadUrl',
                    url: url,
                    timestamp: Date.now()
                };

                // Flag JavaScript URLs as potential XSS vectors
                if (url && (url.indexOf('javascript:') === 0)) {
                    entry.risk = 'high';
                    entry.note = 'JavaScript URL loaded in WebView -- potential XSS';
                    findings.push(entry);
                }
                // Flag file:// protocol access
                if (url && url.indexOf('file://') === 0) {
                    entry.risk = 'medium';
                    entry.note = 'Local file access via WebView';
                    findings.push(entry);
                }

                send(entry);
                return this.loadUrl(url);
            };

            WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
                var hdrs = {};
                if (headers) {
                    var iter = headers.entrySet().iterator();
                    while (iter.hasNext()) {
                        var entry = iter.next();
                        hdrs[entry.getKey().toString()] = entry.getValue().toString();
                    }
                }
                send({
                    type: 'webview_hook',
                    method: 'loadUrl',
                    url: url,
                    headers: hdrs,
                    timestamp: Date.now()
                });
                return this.loadUrl(url, headers);
            };
            send({ type: 'webview_hook', hook: 'loadUrl', status: 'hooked' });
        } catch (e) {
            send({ type: 'webview_hook', hook: 'loadUrl', status: 'failed', error: e.toString() });
        }

        // --- loadData / loadDataWithBaseURL ---
        try {
            WebView.loadData.implementation = function (data, mimeType, encoding) {
                send({
                    type: 'webview_hook',
                    method: 'loadData',
                    data_length: data ? data.length : 0,
                    mime_type: mimeType,
                    encoding: encoding,
                    data_preview: data ? data.substring(0, 500) : '',
                    timestamp: Date.now()
                });
                return this.loadData(data, mimeType, encoding);
            };
        } catch (e) { }

        try {
            WebView.loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
                var entry = {
                    type: 'webview_hook',
                    method: 'loadDataWithBaseURL',
                    base_url: baseUrl,
                    data_length: data ? data.length : 0,
                    mime_type: mimeType,
                    history_url: historyUrl,
                    data_preview: data ? data.substring(0, 500) : '',
                    timestamp: Date.now()
                };
                send(entry);
                return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
            };
        } catch (e) { }

        // --- evaluateJavascript ---
        try {
            WebView.evaluateJavascript.implementation = function (script, callback) {
                var entry = {
                    type: 'webview_hook',
                    method: 'evaluateJavascript',
                    script_length: script ? script.length : 0,
                    script_preview: script ? script.substring(0, 1000) : '',
                    timestamp: Date.now()
                };

                // Flag eval of external / user-controlled JS
                if (script && script.length > 0) {
                    entry.risk = 'medium';
                    entry.note = 'JavaScript evaluated in WebView context';
                    findings.push(entry);
                }

                send(entry);
                return this.evaluateJavascript(script, callback);
            };
            send({ type: 'webview_hook', hook: 'evaluateJavascript', status: 'hooked' });
        } catch (e) {
            send({ type: 'webview_hook', hook: 'evaluateJavascript', status: 'failed', error: e.toString() });
        }

        // --- addJavascriptInterface (critical: exposes Java to JS) ---
        try {
            WebView.addJavascriptInterface.implementation = function (obj, name) {
                var className = obj ? obj.getClass().getName() : 'null';
                var entry = {
                    type: 'webview_hook',
                    method: 'addJavascriptInterface',
                    interface_name: name,
                    object_class: className,
                    risk: 'high',
                    note: 'Java object exposed to JavaScript via @JavascriptInterface',
                    timestamp: Date.now()
                };
                findings.push(entry);
                send(entry);
                return this.addJavascriptInterface(obj, name);
            };
            send({ type: 'webview_hook', hook: 'addJavascriptInterface', status: 'hooked' });
        } catch (e) {
            send({ type: 'webview_hook', hook: 'addJavascriptInterface', status: 'failed', error: e.toString() });
        }

        // --- WebSettings security-relevant methods ---
        try {
            var WebSettings = Java.use('android.webkit.WebSettings');

            WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
                send({
                    type: 'webview_hook',
                    method: 'setJavaScriptEnabled',
                    enabled: enabled,
                    timestamp: Date.now()
                });
                return this.setJavaScriptEnabled(enabled);
            };

            WebSettings.setAllowFileAccess.implementation = function (allow) {
                if (allow) {
                    var entry = {
                        type: 'webview_hook',
                        method: 'setAllowFileAccess',
                        enabled: true,
                        risk: 'medium',
                        note: 'WebView file access enabled',
                        timestamp: Date.now()
                    };
                    findings.push(entry);
                    send(entry);
                }
                return this.setAllowFileAccess(allow);
            };

            WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function (allow) {
                if (allow) {
                    var entry = {
                        type: 'webview_hook',
                        method: 'setAllowUniversalAccessFromFileURLs',
                        enabled: true,
                        risk: 'critical',
                        note: 'Universal file access from file URLs -- SOP bypass',
                        timestamp: Date.now()
                    };
                    findings.push(entry);
                    send(entry);
                }
                return this.setAllowUniversalAccessFromFileURLs(allow);
            };

            WebSettings.setAllowFileAccessFromFileURLs.implementation = function (allow) {
                if (allow) {
                    findings.push({
                        type: 'webview_hook',
                        method: 'setAllowFileAccessFromFileURLs',
                        enabled: true,
                        risk: 'high',
                        note: 'File-to-file URL access enabled'
                    });
                }
                send({ type: 'webview_hook', method: 'setAllowFileAccessFromFileURLs', enabled: allow, timestamp: Date.now() });
                return this.setAllowFileAccessFromFileURLs(allow);
            };

            send({ type: 'webview_hook', hook: 'WebSettings', status: 'hooked' });
        } catch (e) {
            send({ type: 'webview_hook', hook: 'WebSettings', status: 'failed', error: e.toString() });
        }

        send({ type: 'webview_hook', status: 'complete' });
    });
})();
