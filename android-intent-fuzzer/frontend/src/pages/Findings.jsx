import React, { useState, useEffect, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api';
import FindingCard from '../components/FindingCard';

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Findings() {
  const { scanId } = useParams();
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(scanId || '');
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState('severity');
  const [filterPlugin, setFilterPlugin] = useState('all');
  const [filterValidation, setFilterValidation] = useState('all');
  const [expandedId, setExpandedId] = useState(null);

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
    api.getFindings(id)
      .then((data) => setFindings(Array.isArray(data) ? data : data.findings || []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [scanId, activeScan]);

  const plugins = useMemo(
    () => [...new Set(findings.map((f) => f.plugin).filter(Boolean))],
    [findings]
  );

  const filtered = useMemo(() => {
    let list = [...findings];
    if (filterPlugin !== 'all') list = list.filter((f) => f.plugin === filterPlugin);
    if (filterValidation !== 'all') list = list.filter((f) => (f.validation_status || 'unconfirmed') === filterValidation);
    list.sort((a, b) => {
      if (sortBy === 'severity') {
        return (severityOrder[(a.severity || 'info').toLowerCase()] || 4) -
               (severityOrder[(b.severity || 'info').toLowerCase()] || 4);
      }
      if (sortBy === 'title') return (a.title || '').localeCompare(b.title || '');
      if (sortBy === 'component') return (a.component || '').localeCompare(b.component || '');
      return 0;
    });
    return list;
  }, [findings, filterPlugin, filterValidation, sortBy]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => {
      const sev = (f.severity || 'info').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
  }, [findings]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-2xl font-bold text-white">Findings</h2>
        {!scanId && scans.length > 0 && (
          <select
            value={activeScan}
            onChange={(e) => setActiveScan(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.package_name || s.apk_name || s.id}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Severity summary */}
      <div className="flex flex-wrap gap-3">
        {[
          { key: 'critical', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
          { key: 'high', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
          { key: 'medium', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
          { key: 'low', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
          { key: 'info', color: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
        ].map(({ key, color }) => (
          <div key={key} className={`px-4 py-2 rounded-lg border ${color} text-center min-w-[80px]`}>
            <p className="text-xl font-bold">{severityCounts[key]}</p>
            <p className="text-xs uppercase">{key}</p>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Sort:</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded px-2 py-1 text-xs text-white focus:outline-none"
          >
            <option value="severity">Severity</option>
            <option value="title">Title</option>
            <option value="component">Component</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Plugin:</span>
          <select
            value={filterPlugin}
            onChange={(e) => setFilterPlugin(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded px-2 py-1 text-xs text-white focus:outline-none"
          >
            <option value="all">All</option>
            {plugins.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Validation:</span>
          <select
            value={filterValidation}
            onChange={(e) => setFilterValidation(e.target.value)}
            className="bg-slate-800 border border-slate-600 rounded px-2 py-1 text-xs text-white focus:outline-none"
          >
            <option value="all">All</option>
            <option value="confirmed">Confirmed</option>
            <option value="unconfirmed">Unconfirmed</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>

        <span className="text-xs text-slate-500 ml-auto">{filtered.length} finding{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Findings list */}
      {loading ? (
        <div className="text-center py-12 text-slate-400">Loading findings...</div>
      ) : filtered.length === 0 ? (
        <div className="bg-card border border-slate-700 rounded-lg p-12 text-center">
          <svg className="w-12 h-12 mx-auto text-slate-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-slate-400">No findings{filterPlugin !== 'all' || filterValidation !== 'all' ? ' matching filters' : ''}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((finding) => (
            <FindingCard
              key={finding.id || finding.title}
              finding={finding}
              expanded={expandedId === (finding.id || finding.title)}
              onToggle={() =>
                setExpandedId(expandedId === (finding.id || finding.title) ? null : (finding.id || finding.title))
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}
