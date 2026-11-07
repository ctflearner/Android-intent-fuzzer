import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { api } from '../api';

export default function Report() {
  const { scanId } = useParams();
  const [reportHtml, setReportHtml] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
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

  const fetchReport = async () => {
    const id = scanId || activeScan;
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const html = await api.getReport(id, 'html');
      setReportHtml(html);
    } catch (err) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const id = scanId || activeScan;
    if (id) fetchReport();
  }, [scanId, activeScan]);

  const handleDownloadHtml = () => {
    if (!reportHtml) return;
    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intent-hunter-report-${scanId || activeScan}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = async () => {
    const id = scanId || activeScan;
    if (!id) return;
    try {
      const res = await fetch(`/api/scans/${id}/report?format=pdf`);
      if (!res.ok) throw new Error(`${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `intent-hunter-report-${id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('PDF download failed:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-2xl font-bold text-white">Report</h2>
        <div className="flex items-center gap-3">
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
          <button
            onClick={fetchReport}
            disabled={loading}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-white font-medium transition-colors"
          >
            {loading ? 'Generating...' : 'Regenerate'}
          </button>
          <button
            onClick={handleDownloadHtml}
            disabled={!reportHtml}
            className="px-4 py-2 bg-accent hover:bg-blue-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm text-white font-medium transition-colors"
          >
            Download HTML
          </button>
          <button
            onClick={handleDownloadPdf}
            disabled={!reportHtml}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm text-white font-medium transition-colors"
          >
            Download PDF
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 text-sm">{error}</div>
      )}

      {loading ? (
        <div className="bg-card border border-slate-700 rounded-lg p-12 text-center text-slate-400">
          <svg className="w-8 h-8 mx-auto mb-3 animate-spin text-accent" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          Generating report...
        </div>
      ) : reportHtml ? (
        <div className="bg-white rounded-lg overflow-hidden" style={{ minHeight: '600px' }}>
          <iframe
            srcDoc={reportHtml}
            className="w-full border-0"
            style={{ minHeight: '80vh' }}
            title="Scan Report"
            sandbox="allow-scripts allow-same-origin"
          />
        </div>
      ) : (
        <div className="bg-card border border-slate-700 rounded-lg p-12 text-center">
          <svg className="w-12 h-12 mx-auto text-slate-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p className="text-slate-400">Select a scan to generate a report</p>
        </div>
      )}
    </div>
  );
}
