import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api';
import LogcatStream from '../components/LogcatStream';

export default function Explorer() {
  const { scanId } = useParams();
  const [staticData, setStaticData] = useState(null);
  const [components, setComponents] = useState([]);
  const [selectedComponent, setSelectedComponent] = useState('');
  const [intentAction, setIntentAction] = useState('');
  const [intentCategory, setIntentCategory] = useState('');
  const [intentData, setIntentData] = useState('');
  const [intentExtras, setIntentExtras] = useState('');
  const [intentType, setIntentType] = useState('activity');
  const [sending, setSending] = useState(false);
  const [response, setResponse] = useState(null);
  const [logLines, setLogLines] = useState([]);
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(scanId || '');

  useEffect(() => {
    if (!scanId) {
      api.listScans().then((data) => {
        const list = Array.isArray(data) ? data : data.scans || [];
        setScans(list);
        if (list.length > 0 && !activeScan) setActiveScan(list[0].id);
      }).catch(() => {});
    }
  }, [scanId]);

  useEffect(() => {
    const id = scanId || activeScan;
    if (!id) return;
    api.getStatic(id).then((data) => {
      setStaticData(data);
      const all = [
        ...(data.activities || []).map((c) => ({ ...c, type: 'activity' })),
        ...(data.services || []).map((c) => ({ ...c, type: 'service' })),
        ...(data.receivers || []).map((c) => ({ ...c, type: 'receiver' })),
        ...(data.providers || []).map((c) => ({ ...c, type: 'provider' })),
      ];
      setComponents(all);
    }).catch(() => {});
  }, [scanId, activeScan]);

  const handleComponentSelect = (name) => {
    setSelectedComponent(name);
    const comp = components.find((c) => c.name === name);
    if (comp) {
      setIntentType(comp.type);
      const filter = comp.intent_filters?.[0];
      if (filter) {
        setIntentAction(filter.actions?.[0] || '');
        setIntentCategory(filter.categories?.[0] || '');
        const d = filter.data?.[0];
        if (d) setIntentData(d.scheme ? `${d.scheme}://${d.host || ''}${d.path || ''}` : '');
      } else {
        setIntentAction('');
        setIntentCategory('');
        setIntentData('');
      }
      setIntentExtras('');
    }
  };

  const handleSend = async () => {
    setSending(true);
    setResponse(null);
    setLogLines([]);

    try {
      const id = scanId || activeScan;
      const body = {
        component: selectedComponent,
        action: intentAction || undefined,
        category: intentCategory || undefined,
        data: intentData || undefined,
        extras: intentExtras ? JSON.parse(intentExtras) : undefined,
        type: intentType,
      };

      const res = await fetch(`/api/scans/${id}/send-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const result = await res.json().catch(() => ({ status: res.status }));
      setResponse(result);

      if (result.logcat) {
        setLogLines(Array.isArray(result.logcat) ? result.logcat : result.logcat.split('\n'));
      }
    } catch (err) {
      setResponse({ error: err.message });
    } finally {
      setSending(false);
    }
  };

  const buildAdbCommand = () => {
    const parts = ['adb shell am'];
    if (intentType === 'activity') parts.push('start');
    else if (intentType === 'service') parts.push('startservice');
    else if (intentType === 'receiver') parts.push('broadcast');

    if (intentAction) parts.push(`-a "${intentAction}"`);
    if (intentCategory) parts.push(`-c "${intentCategory}"`);
    if (intentData) parts.push(`-d "${intentData}"`);
    if (selectedComponent) parts.push(`-n "${selectedComponent}"`);

    return parts.join(' \\\n  ');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-2xl font-bold text-white">Intent Explorer</h2>
        {!scanId && scans.length > 0 && (
          <select
            value={activeScan}
            onChange={(e) => setActiveScan(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>{s.package_name || s.apk_name || s.id}</option>
            ))}
          </select>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Intent builder */}
        <div className="space-y-4">
          <div className="bg-card border border-slate-700 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-white">Intent Builder</h3>

            {/* Component */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Component</label>
              <select
                value={selectedComponent}
                onChange={(e) => handleComponentSelect(e.target.value)}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
              >
                <option value="">Select component...</option>
                {components.map((c) => (
                  <option key={c.name} value={c.name}>
                    [{c.type[0].toUpperCase()}] {c.name?.split('.').pop()} {c.exported ? '(exported)' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* Type */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Type</label>
              <div className="flex gap-2">
                {['activity', 'service', 'receiver'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setIntentType(t)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      intentType === t ? 'bg-accent text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Action */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Action</label>
              <input
                type="text"
                value={intentAction}
                onChange={(e) => setIntentAction(e.target.value)}
                placeholder="android.intent.action.VIEW"
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-accent font-mono"
              />
            </div>

            {/* Category */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Category</label>
              <input
                type="text"
                value={intentCategory}
                onChange={(e) => setIntentCategory(e.target.value)}
                placeholder="android.intent.category.DEFAULT"
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-accent font-mono"
              />
            </div>

            {/* Data URI */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Data URI</label>
              <input
                type="text"
                value={intentData}
                onChange={(e) => setIntentData(e.target.value)}
                placeholder="content://com.example.provider/data"
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-accent font-mono"
              />
            </div>

            {/* Extras (JSON) */}
            <div>
              <label className="block text-xs text-slate-400 uppercase mb-1">Extras (JSON)</label>
              <textarea
                value={intentExtras}
                onChange={(e) => setIntentExtras(e.target.value)}
                placeholder='{"key": "value", "count": 42}'
                rows={3}
                className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-accent font-mono resize-y"
              />
            </div>

            <button
              onClick={handleSend}
              disabled={!selectedComponent || sending}
              className="w-full py-2.5 bg-accent hover:bg-blue-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold text-white transition-colors"
            >
              {sending ? 'Sending...' : 'Send Intent'}
            </button>
          </div>

          {/* ADB command preview */}
          {selectedComponent && (
            <div className="bg-card border border-slate-700 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs text-slate-400 uppercase font-semibold">ADB Command</h4>
                <button
                  onClick={() => navigator.clipboard.writeText(buildAdbCommand())}
                  className="px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs text-slate-300"
                >
                  Copy
                </button>
              </div>
              <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">{buildAdbCommand()}</pre>
            </div>
          )}

          {/* Response */}
          {response && (
            <div className="bg-card border border-slate-700 rounded-lg p-4">
              <h4 className="text-xs text-slate-400 uppercase font-semibold mb-2">Response</h4>
              <pre className="bg-slate-900 rounded p-3 text-xs text-slate-300 font-mono whitespace-pre-wrap overflow-x-auto max-h-48 overflow-y-auto">
                {JSON.stringify(response, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Right: Emulator + logcat */}
        <div className="space-y-4">
          {/* Emulator view */}
          <div className="bg-card border border-slate-700 rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-slate-700">
              <h3 className="text-sm font-semibold text-white">Emulator View</h3>
              <span className="text-xs text-slate-400">noVNC :6080</span>
            </div>
            <div className="aspect-[9/16] max-h-[500px] bg-black">
              <iframe
                src="http://localhost:6080"
                className="w-full h-full border-0"
                title="Android Emulator"
                sandbox="allow-scripts allow-same-origin"
                loading="lazy"
              />
            </div>
          </div>

          {/* Logcat output */}
          <div className="bg-card border border-slate-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">Logcat Output</h3>
            <div className="h-48">
              <LogcatStream lines={logLines} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
