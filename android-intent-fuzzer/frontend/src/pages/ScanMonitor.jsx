import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, connectWebSocket } from '../api';
import LogcatStream from '../components/LogcatStream';
import CoverageChart from '../components/CoverageChart';

export default function ScanMonitor() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [logLines, setLogLines] = useState([]);
  const [crashes, setCrashes] = useState([]);
  const [progress, setProgress] = useState({
    phase: 'Initializing',
    plugin: '',
    intents_sent: 0,
    crashes: 0,
    coverage: 0,
    percent: 0,
  });
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    api.getScan(scanId).then(setScan).catch(console.error);
  }, [scanId]);

  useEffect(() => {
    const ws = connectWebSocket(
      scanId,
      (msg) => {
        setConnected(true);
        switch (msg.type) {
          case 'progress':
            setProgress((prev) => ({ ...prev, ...msg.data }));
            break;
          case 'logcat':
            setLogLines((prev) => [...prev, msg.data]);
            break;
          case 'crash':
            setCrashes((prev) => [...prev, msg.data]);
            setProgress((prev) => ({ ...prev, crashes: prev.crashes + 1 }));
            break;
          case 'phase':
            setProgress((prev) => ({ ...prev, phase: msg.data }));
            break;
          case 'complete':
            setProgress((prev) => ({ ...prev, phase: 'Complete', percent: 100 }));
            api.getScan(scanId).then(setScan);
            break;
          case 'error':
            setProgress((prev) => ({ ...prev, phase: `Error: ${msg.data}` }));
            break;
          default:
            if (typeof msg.data === 'string') {
              setLogLines((prev) => [...prev, msg.data]);
            }
        }
      },
      () => setConnected(false)
    );
    wsRef.current = ws;
    return () => ws.close();
  }, [scanId]);

  const handleCancel = async () => {
    try {
      await api.cancelScan(scanId);
      setProgress((prev) => ({ ...prev, phase: 'Cancelled' }));
    } catch (err) {
      console.error(err);
    }
  };

  const isRunning = scan?.status === 'running' || (progress.phase !== 'Complete' && progress.phase !== 'Cancelled' && !progress.phase.startsWith('Error'));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">Scan Monitor</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            {scan?.package_name || scan?.apk_name || scanId}
            <span className="mx-2 text-slate-600">|</span>
            <span className={connected ? 'text-green-400' : 'text-slate-500'}>
              {connected ? 'Live' : 'Disconnected'}
            </span>
          </p>
        </div>
        <div className="flex gap-2">
          {isRunning && (
            <button
              onClick={handleCancel}
              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 rounded-lg text-sm text-red-400 font-medium transition-colors"
            >
              Cancel
            </button>
          )}
          <Link
            to={`/scan/${scanId}/surface`}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-white font-medium transition-colors"
          >
            Attack Surface
          </Link>
          <Link
            to={`/scan/${scanId}/findings`}
            className="px-4 py-2 bg-accent hover:bg-blue-600 rounded-lg text-sm text-white font-medium transition-colors"
          >
            Findings
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left panel: progress */}
        <div className="lg:col-span-1 space-y-4">
          {/* Overall progress */}
          <div className="bg-card border border-slate-700 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-400 uppercase mb-4">Progress</h3>
            <div className="w-full h-3 bg-slate-700 rounded-full overflow-hidden mb-3">
              <div
                className="h-full bg-accent rounded-full transition-all duration-300"
                style={{ width: `${progress.percent}%` }}
              />
            </div>
            <div className="flex justify-between text-xs text-slate-400">
              <span>{progress.phase}</span>
              <span>{progress.percent}%</span>
            </div>
          </div>

          {/* Phase & plugin */}
          <div className="bg-card border border-slate-700 rounded-lg p-5 space-y-3">
            <div>
              <span className="text-xs text-slate-400">Phase</span>
              <p className="text-sm text-white font-medium">{progress.phase}</p>
            </div>
            {progress.plugin && (
              <div>
                <span className="text-xs text-slate-400">Active Plugin</span>
                <p className="text-sm text-accent font-medium">{progress.plugin}</p>
              </div>
            )}
          </div>

          {/* Counters */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-card border border-slate-700 rounded-lg p-4 text-center">
              <p className="text-2xl font-bold text-white">{progress.intents_sent}</p>
              <p className="text-xs text-slate-400 mt-1">Intents Sent</p>
            </div>
            <div className="bg-card border border-slate-700 rounded-lg p-4 text-center">
              <p className={`text-2xl font-bold ${progress.crashes > 0 ? 'text-red-400' : 'text-white'}`}>
                {progress.crashes}
              </p>
              <p className="text-xs text-slate-400 mt-1">Crashes</p>
            </div>
          </div>

          {/* Coverage */}
          <div className="bg-card border border-slate-700 rounded-lg p-5">
            <CoverageChart percentage={progress.coverage} label="Component Coverage" />
          </div>
        </div>

        {/* Right panel: live feeds */}
        <div className="lg:col-span-2 space-y-4">
          {/* Logcat */}
          <div className="bg-card border border-slate-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">Logcat Stream</h3>
            <div className="h-80">
              <LogcatStream lines={logLines} />
            </div>
          </div>

          {/* Crash feed */}
          <div className="bg-card border border-slate-700 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">
              Crash Feed
              {crashes.length > 0 && (
                <span className="ml-2 px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                  {crashes.length}
                </span>
              )}
            </h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {crashes.length === 0 ? (
                <p className="text-sm text-slate-500 py-4 text-center">No crashes detected</p>
              ) : (
                crashes.map((crash, i) => (
                  <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="w-2 h-2 rounded-full bg-red-500" />
                      <span className="text-xs text-red-400 font-medium">{crash.type || 'Crash'}</span>
                      <span className="text-xs text-slate-500 ml-auto">{crash.component || ''}</span>
                    </div>
                    <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap line-clamp-3">
                      {crash.message || crash.stacktrace || JSON.stringify(crash)}
                    </pre>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
