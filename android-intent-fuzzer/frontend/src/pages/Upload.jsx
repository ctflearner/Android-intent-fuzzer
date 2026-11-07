import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';

export default function Upload() {
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [plugins, setPlugins] = useState([]);
  const [devices, setDevices] = useState([]);
  const [selectedPlugins, setSelectedPlugins] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [staticOnly, setStaticOnly] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    api.listPlugins().then((data) => {
      const list = Array.isArray(data) ? data : data.plugins || [];
      setPlugins(list);
      setSelectedPlugins(list.map((p) => p.name || p.id));
    }).catch(() => {});

    api.listDevices().then((data) => {
      const list = Array.isArray(data) ? data : data.devices || [];
      setDevices(list);
      if (list.length > 0) setSelectedDevice(list[0].serial || list[0].id || '');
    }).catch(() => {});
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => setDragOver(false), []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f && f.name.endsWith('.apk')) {
      setFile(f);
      setError(null);
    } else {
      setError('Please drop a valid .apk file');
    }
  }, []);

  const handleFileSelect = (e) => {
    const f = e.target.files[0];
    if (f) {
      setFile(f);
      setError(null);
    }
  };

  const togglePlugin = (name) => {
    setSelectedPlugins((prev) =>
      prev.includes(name) ? prev.filter((p) => p !== name) : [...prev, name]
    );
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    setProgress('Uploading APK...');

    try {
      const formData = new FormData();
      formData.append('apk', file);
      formData.append('config', JSON.stringify({
        static_only: staticOnly,
        plugins: selectedPlugins,
        device: selectedDevice || undefined,
      }));

      const scan = await api.createScan(formData);
      setProgress('Scan created. Starting...');

      if (!staticOnly) {
        await api.startScan(scan.id);
      }
      navigate(`/scan/${scan.id}`);
    } catch (err) {
      setError(err.message || 'Upload failed');
      setUploading(false);
      setProgress(null);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h2 className="text-2xl font-bold text-white">Upload APK</h2>

      {/* Drop zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors cursor-pointer ${
          dragOver
            ? 'border-accent bg-accent/10'
            : file
            ? 'border-green-500/50 bg-green-500/5'
            : 'border-slate-600 hover:border-slate-500 bg-card'
        }`}
        onClick={() => document.getElementById('apk-input').click()}
      >
        <input
          id="apk-input"
          type="file"
          accept=".apk"
          onChange={handleFileSelect}
          className="hidden"
        />
        {file ? (
          <div>
            <svg className="w-12 h-12 mx-auto text-green-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-white font-medium">{file.name}</p>
            <p className="text-sm text-slate-400 mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
            <p className="text-xs text-slate-500 mt-2">Click or drop to replace</p>
          </div>
        ) : (
          <div>
            <svg className="w-12 h-12 mx-auto text-slate-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <p className="text-white font-medium">Drop APK file here</p>
            <p className="text-sm text-slate-400 mt-1">or click to browse</p>
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-400 text-sm">{error}</div>
      )}

      {/* Options */}
      <div className="bg-card border border-slate-700 rounded-lg p-5 space-y-5">
        <h3 className="text-sm font-semibold text-white">Scan Options</h3>

        {/* Static only toggle */}
        <label className="flex items-center gap-3 cursor-pointer">
          <div
            className={`w-10 h-5 rounded-full transition-colors relative ${staticOnly ? 'bg-accent' : 'bg-slate-600'}`}
            onClick={(e) => { e.preventDefault(); setStaticOnly(!staticOnly); }}
          >
            <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${staticOnly ? 'translate-x-5' : 'translate-x-0.5'}`} />
          </div>
          <div>
            <span className="text-sm text-white">Static Analysis Only</span>
            <p className="text-xs text-slate-400">Skip dynamic fuzzing, only analyze APK contents</p>
          </div>
        </label>

        {/* Device selection */}
        {!staticOnly && (
          <div>
            <label className="block text-xs text-slate-400 uppercase mb-2">Target Device</label>
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
            >
              <option value="">Auto-select</option>
              {devices.map((d, i) => (
                <option key={i} value={d.serial || d.id}>
                  {d.model || d.serial || `Device ${i + 1}`} (Android {d.android_version || '?'})
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Plugin checkboxes */}
        {plugins.length > 0 && (
          <div>
            <label className="block text-xs text-slate-400 uppercase mb-2">Plugins</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {plugins.map((p) => {
                const name = p.name || p.id;
                const checked = selectedPlugins.includes(name);
                return (
                  <label
                    key={name}
                    className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                      checked ? 'border-accent/50 bg-accent/10' : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => togglePlugin(name)}
                      className="w-4 h-4 rounded border-slate-500 bg-slate-700 text-accent focus:ring-accent focus:ring-offset-0"
                    />
                    <div>
                      <span className="text-sm text-white">{name}</span>
                      {p.description && <p className="text-xs text-slate-400">{p.description}</p>}
                    </div>
                  </label>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Upload button */}
      <button
        onClick={handleUpload}
        disabled={!file || uploading}
        className="w-full py-3 bg-accent hover:bg-blue-600 disabled:bg-slate-700 disabled:text-slate-500 rounded-lg text-sm font-semibold text-white transition-colors"
      >
        {uploading ? progress || 'Uploading...' : 'Start Scan'}
      </button>
    </div>
  );
}
