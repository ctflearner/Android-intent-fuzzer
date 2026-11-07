import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api';

const typeColors = {
  activity: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400', badge: 'bg-blue-500/20' },
  service: { bg: 'bg-purple-500/10', border: 'border-purple-500/30', text: 'text-purple-400', badge: 'bg-purple-500/20' },
  receiver: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400', badge: 'bg-green-500/20' },
  provider: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', badge: 'bg-orange-500/20' },
};

function ComponentCard({ component, type }) {
  const [expanded, setExpanded] = useState(false);
  const colors = typeColors[type] || typeColors.activity;

  return (
    <div className={`${colors.bg} border ${colors.border} rounded-lg overflow-hidden`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
      >
        {component.exported && (
          <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px] font-bold uppercase">
            Exported
          </span>
        )}
        <span className="flex-1 text-sm text-white font-medium truncate">
          {component.name?.split('.').pop() || component.name}
        </span>
        <svg
          className={`w-4 h-4 ${colors.text} transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/30 pt-3 space-y-3">
          <div>
            <span className="text-xs text-slate-400">Full Name</span>
            <p className="text-xs text-slate-300 font-mono break-all">{component.name}</p>
          </div>

          {component.permission && (
            <div>
              <span className="text-xs text-slate-400">Permission</span>
              <p className="text-xs text-yellow-400 font-mono">{component.permission}</p>
            </div>
          )}

          {component.intent_filters && component.intent_filters.length > 0 && (
            <div>
              <span className="text-xs text-slate-400">Intent Filters</span>
              {component.intent_filters.map((filter, i) => (
                <div key={i} className="mt-1 bg-slate-900/50 rounded p-2 space-y-1">
                  {filter.actions?.map((a, j) => (
                    <p key={j} className="text-xs font-mono">
                      <span className="text-slate-500">action:</span>{' '}
                      <span className="text-green-400">{a}</span>
                    </p>
                  ))}
                  {filter.categories?.map((c, j) => (
                    <p key={j} className="text-xs font-mono">
                      <span className="text-slate-500">category:</span>{' '}
                      <span className="text-blue-400">{c}</span>
                    </p>
                  ))}
                  {filter.data?.map((d, j) => (
                    <p key={j} className="text-xs font-mono">
                      <span className="text-slate-500">data:</span>{' '}
                      <span className="text-orange-400">{d.scheme ? `${d.scheme}://${d.host || '*'}${d.path || ''}` : JSON.stringify(d)}</span>
                    </p>
                  ))}
                </div>
              ))}
            </div>
          )}

          {component.deep_links && component.deep_links.length > 0 && (
            <div>
              <span className="text-xs text-slate-400">Deep Links</span>
              {component.deep_links.map((link, i) => (
                <p key={i} className="text-xs text-cyan-400 font-mono mt-0.5">{link}</p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackSurface() {
  const { scanId } = useParams();
  const [staticData, setStaticData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    if (!scanId) return;
    api.getStatic(scanId)
      .then(setStaticData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scanId]);

  if (!scanId) {
    return (
      <div className="text-center py-12 text-slate-400">
        <p>Select a scan to view its attack surface</p>
      </div>
    );
  }

  if (loading) {
    return <div className="text-center py-12 text-slate-400">Loading static analysis...</div>;
  }

  if (!staticData) {
    return <div className="text-center py-12 text-slate-400">No static analysis data available</div>;
  }

  const sections = [
    { key: 'activities', label: 'Activities', type: 'activity' },
    { key: 'services', label: 'Services', type: 'service' },
    { key: 'receivers', label: 'Receivers', type: 'receiver' },
    { key: 'providers', label: 'Providers', type: 'provider' },
  ];

  const counts = {};
  const exportedCounts = {};
  sections.forEach(({ key }) => {
    const list = staticData[key] || [];
    counts[key] = list.length;
    exportedCounts[key] = list.filter((c) => c.exported).length;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">Attack Surface</h2>
          <p className="text-sm text-slate-400 mt-0.5">{staticData.package_name || ''}</p>
        </div>
        <div className="flex gap-2">
          {['all', 'exported'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                filter === f ? 'bg-accent text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              {f === 'all' ? 'All' : 'Exported Only'}
            </button>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {sections.map(({ key, label, type }) => {
          const colors = typeColors[type];
          return (
            <div key={key} className={`${colors.bg} border ${colors.border} rounded-lg p-4`}>
              <p className={`text-xs ${colors.text} uppercase font-semibold`}>{label}</p>
              <p className="text-2xl font-bold text-white mt-1">{counts[key]}</p>
              <p className="text-xs text-slate-400 mt-0.5">{exportedCounts[key]} exported</p>
            </div>
          );
        })}
      </div>

      {/* Component groups */}
      {sections.map(({ key, label, type }) => {
        let list = staticData[key] || [];
        if (filter === 'exported') list = list.filter((c) => c.exported);
        if (list.length === 0) return null;

        return (
          <div key={key}>
            <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">
              {label} ({list.length})
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {list.map((comp, i) => (
                <ComponentCard key={i} component={comp} type={type} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
