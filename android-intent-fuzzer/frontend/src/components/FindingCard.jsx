import React, { useState } from 'react';

const severityColors = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
};

const validationColors = {
  confirmed: 'bg-green-500/20 text-green-400',
  unconfirmed: 'bg-yellow-500/20 text-yellow-400',
  false_positive: 'bg-slate-500/20 text-slate-400',
};

export default function FindingCard({ finding, expanded: controlledExpanded, onToggle }) {
  const [localExpanded, setLocalExpanded] = useState(false);
  const expanded = controlledExpanded !== undefined ? controlledExpanded : localExpanded;
  const toggle = onToggle || (() => setLocalExpanded(!localExpanded));

  const sev = (finding.severity || 'info').toLowerCase();
  const validation = (finding.validation_status || 'unconfirmed').toLowerCase();

  return (
    <div className="bg-card border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={toggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-700/30 transition-colors"
      >
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${severityColors[sev] || severityColors.info}`}>
          {sev}
        </span>
        <span className="flex-1 text-sm font-medium text-white truncate">{finding.title}</span>
        <span className="text-xs text-slate-400 hidden sm:block">{finding.component}</span>
        <span className="text-xs text-slate-500 hidden md:block">{finding.plugin}</span>
        <span className={`px-2 py-0.5 rounded text-xs ${validationColors[validation] || validationColors.unconfirmed}`}>
          {validation.replace('_', ' ')}
        </span>
        <svg
          className={`w-4 h-4 text-slate-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/50 pt-3 space-y-3">
          {finding.description && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Description</h4>
              <p className="text-sm text-slate-300">{finding.description}</p>
            </div>
          )}

          {finding.poc_command && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">PoC Command</h4>
              <div className="relative">
                <pre className="bg-slate-900 rounded p-3 text-xs text-green-400 overflow-x-auto font-mono">
                  {finding.poc_command}
                </pre>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigator.clipboard.writeText(finding.poc_command);
                  }}
                  className="absolute top-2 right-2 p-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs"
                  title="Copy"
                >
                  Copy
                </button>
              </div>
            </div>
          )}

          {finding.evidence && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Evidence</h4>
              <pre className="bg-slate-900 rounded p-3 text-xs text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.logcat && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Logcat</h4>
              <pre className="bg-slate-900 rounded p-3 text-xs text-slate-300 overflow-x-auto font-mono max-h-48 overflow-y-auto">
                {finding.logcat}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
