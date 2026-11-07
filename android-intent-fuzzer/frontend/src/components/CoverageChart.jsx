import React from 'react';

export default function CoverageChart({ percentage = 0, label = 'Coverage' }) {
  const clamped = Math.min(100, Math.max(0, percentage));
  const color =
    clamped >= 80 ? 'text-green-400' :
    clamped >= 50 ? 'text-yellow-400' :
    clamped >= 25 ? 'text-orange-400' :
    'text-red-400';
  const barColor =
    clamped >= 80 ? 'bg-green-500' :
    clamped >= 50 ? 'bg-yellow-500' :
    clamped >= 25 ? 'bg-orange-500' :
    'bg-red-500';

  return (
    <div className="flex flex-col items-center">
      <span className={`text-4xl font-bold ${color}`}>{clamped.toFixed(1)}%</span>
      <span className="text-xs text-slate-400 mt-1 mb-2">{label}</span>
      <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${barColor} rounded-full transition-all duration-500`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  );
}
