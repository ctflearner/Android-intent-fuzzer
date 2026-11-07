import React, { useState, useEffect } from 'react';
import { api } from '../api';

export default function DevicePanel() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    loadDevices();
    const interval = setInterval(loadDevices, 10000);
    return () => clearInterval(interval);
  }, []);

  async function loadDevices() {
    try {
      const data = await api.listDevices();
      setDevices(Array.isArray(data) ? data : data.devices || []);
    } catch {
      setDevices([]);
    }
  }

  async function handleCreateEmulator() {
    setCreating(true);
    try {
      await api.createEmulator();
      await loadDevices();
    } catch (err) {
      console.error('Failed to create emulator:', err);
    } finally {
      setCreating(false);
    }
  }

  if (devices.length === 0) {
    return (
      <div className="bg-slate-800/50 rounded-lg p-3">
        <div className="flex items-center gap-2 mb-2">
          <span className="w-2 h-2 rounded-full bg-slate-500" />
          <span className="text-xs text-slate-400">No Device</span>
        </div>
        <button
          onClick={handleCreateEmulator}
          disabled={creating}
          className="w-full px-3 py-1.5 bg-accent hover:bg-blue-600 disabled:bg-slate-600 rounded text-xs font-medium text-white transition-colors"
        >
          {creating ? 'Starting...' : 'Start Emulator'}
        </button>
      </div>
    );
  }

  const device = devices[0];
  return (
    <div className="bg-slate-800/50 rounded-lg p-3 space-y-1.5">
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-green-500" />
        <span className="text-xs font-medium text-white truncate">{device.model || device.serial || 'Device'}</span>
      </div>
      <div className="grid grid-cols-2 gap-x-3 text-xs text-slate-400">
        <span>Android</span>
        <span className="text-slate-300">{device.android_version || 'N/A'}</span>
        <span>Root</span>
        <span className={device.rooted ? 'text-green-400' : 'text-slate-500'}>{device.rooted ? 'Yes' : 'No'}</span>
        <span>Frida</span>
        <span className={device.frida ? 'text-green-400' : 'text-slate-500'}>{device.frida ? 'Running' : 'Off'}</span>
      </div>
    </div>
  );
}
