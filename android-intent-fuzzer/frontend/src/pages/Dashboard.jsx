import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';

const statusBadge = {
  running: 'bg-blue-500/20 text-blue-400',
  completed: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-500/20 text-red-400',
  cancelled: 'bg-slate-500/20 text-slate-400',
  pending: 'bg-yellow-500/20 text-yellow-400',
  created: 'bg-slate-500/20 text-slate-300',
};

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function load() {
      try {
        const [scanData, deviceData] = await Promise.all([
          api.listScans().catch(() => []),
          api.listDevices().catch(() => []),
        ]);
        setScans(Array.isArray(scanData) ? scanData : scanData.scans || []);
        setDevices(Array.isArray(deviceData) ? deviceData : deviceData.devices || []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const totalFindings = scans.reduce((sum, s) => sum + (s.findings_count || 0), 0);
  const criticalCount = scans.reduce((sum, s) => sum + (s.critical_count || 0), 0);
  const runningCount = scans.filter((s) => s.status === 'running').length;

  const stats = [
    { label: 'Total Scans', value: scans.length, color: 'text-accent' },
    { label: 'Findings', value: totalFindings, color: 'text-yellow-400' },
    { label: 'Critical', value: criticalCount, color: 'text-red-400' },
    { label: 'Running', value: runningCount, color: 'text-green-400' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <Link
          to="/upload"
          className="px-4 py-2 bg-accent hover:bg-blue-600 rounded-lg text-sm font-medium text-white transition-colors"
        >
          + New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.label} className="bg-card border border-slate-700 rounded-lg p-4">
            <p className="text-xs text-slate-400 uppercase tracking-wide">{stat.label}</p>
            <p className={`text-3xl font-bold mt-1 ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Device cards */}
      {devices.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">Connected Devices</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {devices.map((d, i) => (
              <div key={i} className="bg-card border border-slate-700 rounded-lg p-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                  <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-white">{d.model || d.serial || 'Device'}</p>
                  <p className="text-xs text-slate-400">Android {d.android_version || '?'} {d.rooted ? '| Rooted' : ''}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan history */}
      <div>
        <h3 className="text-sm font-semibold text-slate-400 uppercase mb-3">Scan History</h3>
        {loading ? (
          <div className="bg-card border border-slate-700 rounded-lg p-8 text-center text-slate-400">Loading...</div>
        ) : scans.length === 0 ? (
          <div className="bg-card border border-slate-700 rounded-lg p-8 text-center">
            <p className="text-slate-400 mb-3">No scans yet</p>
            <Link to="/upload" className="text-accent hover:text-blue-400 text-sm font-medium">
              Upload your first APK
            </Link>
          </div>
        ) : (
          <div className="bg-card border border-slate-700 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-slate-400 text-xs uppercase">
                    <th className="text-left px-4 py-3 font-semibold">Package</th>
                    <th className="text-left px-4 py-3 font-semibold">Status</th>
                    <th className="text-left px-4 py-3 font-semibold hidden sm:table-cell">Findings</th>
                    <th className="text-left px-4 py-3 font-semibold hidden md:table-cell">Date</th>
                    <th className="text-right px-4 py-3 font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-700/20 cursor-pointer transition-colors"
                      onClick={() => navigate(`/scan/${scan.id}`)}
                    >
                      <td className="px-4 py-3">
                        <span className="text-white font-medium">{scan.package_name || scan.apk_name || scan.id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusBadge[scan.status] || statusBadge.pending}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 hidden sm:table-cell text-slate-300">{scan.findings_count || 0}</td>
                      <td className="px-4 py-3 hidden md:table-cell text-slate-400 text-xs">
                        {scan.created_at ? new Date(scan.created_at).toLocaleString() : '-'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          to={`/scan/${scan.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-accent hover:text-blue-400 text-xs font-medium"
                        >
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
