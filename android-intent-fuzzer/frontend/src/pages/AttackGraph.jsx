import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api';

const severityColors = {
  critical: { bg: 'bg-red-500/20', border: 'border-red-500/40', text: 'text-red-400', line: '#ef4444' },
  high: { bg: 'bg-orange-500/20', border: 'border-orange-500/40', text: 'text-orange-400', line: '#f97316' },
  medium: { bg: 'bg-yellow-500/20', border: 'border-yellow-500/40', text: 'text-yellow-400', line: '#eab308' },
  low: { bg: 'bg-blue-500/20', border: 'border-blue-500/40', text: 'text-blue-400', line: '#3b82f6' },
  info: { bg: 'bg-slate-500/20', border: 'border-slate-500/40', text: 'text-slate-400', line: '#64748b' },
};

function ChainCard({ chain, index }) {
  const [expanded, setExpanded] = useState(false);
  const steps = chain.steps || chain.findings || [];
  const maxSev = steps.reduce((worst, step) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const stepSev = (step.severity || 'info').toLowerCase();
    return order[stepSev] < order[worst] ? stepSev : worst;
  }, 'info');
  const colors = severityColors[maxSev];

  return (
    <div className={`${colors.bg} border ${colors.border} rounded-lg overflow-hidden`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-white/5 transition-colors"
      >
        <span className="text-lg font-bold text-slate-500">#{index + 1}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-white truncate">{chain.title || chain.name || `Attack Chain ${index + 1}`}</p>
          <p className="text-xs text-slate-400 mt-0.5">{steps.length} step{steps.length !== 1 ? 's' : ''} | Impact: {chain.impact || maxSev}</p>
        </div>
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${colors.bg} ${colors.text} border ${colors.border}`}>
          {maxSev}
        </span>
        <svg
          className={`w-5 h-5 text-slate-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-5 pb-5 border-t border-slate-700/30 pt-4">
          {chain.description && (
            <p className="text-sm text-slate-300 mb-4">{chain.description}</p>
          )}

          {/* Chain visualization */}
          <div className="space-y-0">
            {steps.map((step, i) => {
              const sev = (step.severity || 'info').toLowerCase();
              const sc = severityColors[sev];
              return (
                <div key={i}>
                  <div className={`${sc.bg} border ${sc.border} rounded-lg p-4`}>
                    <div className="flex items-start gap-3">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-slate-800 border-2 border-slate-600 flex items-center justify-center">
                        <span className="text-xs font-bold text-white">{i + 1}</span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${sc.bg} ${sc.text}`}>
                            {sev}
                          </span>
                          <span className="text-sm font-medium text-white">{step.title || step.name}</span>
                        </div>
                        {step.component && (
                          <p className="text-xs text-slate-400 font-mono mt-1">{step.component}</p>
                        )}
                        {step.description && (
                          <p className="text-xs text-slate-300 mt-1.5">{step.description}</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Arrow connector */}
                  {i < steps.length - 1 && (
                    <div className="flex justify-center py-1">
                      <div className="flex flex-col items-center">
                        <div className="w-0.5 h-4 bg-slate-600" />
                        <svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Chain summary */}
          {chain.remediation && (
            <div className="mt-4 bg-slate-900/50 rounded-lg p-3">
              <h4 className="text-xs text-slate-400 uppercase font-semibold mb-1">Remediation</h4>
              <p className="text-sm text-slate-300">{chain.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackGraph() {
  const { scanId } = useParams();
  const [chains, setChains] = useState([]);
  const [loading, setLoading] = useState(true);
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
    if (!id) { setLoading(false); return; }
    setLoading(true);
    api.getChains(id)
      .then((data) => setChains(Array.isArray(data) ? data : data.chains || []))
      .catch(() => setChains([]))
      .finally(() => setLoading(false));
  }, [scanId, activeScan]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-2xl font-bold text-white">Attack Chains</h2>
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

      {loading ? (
        <div className="text-center py-12 text-slate-400">Loading attack chains...</div>
      ) : chains.length === 0 ? (
        <div className="bg-card border border-slate-700 rounded-lg p-12 text-center">
          <svg className="w-12 h-12 mx-auto text-slate-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <p className="text-slate-400">No attack chains identified</p>
          <p className="text-xs text-slate-500 mt-1">Chains are built from correlated findings after scanning</p>
        </div>
      ) : (
        <div className="space-y-4">
          {chains.map((chain, i) => (
            <ChainCard key={chain.id || i} chain={chain} index={i} />
          ))}
        </div>
      )}
    </div>
  );
}
