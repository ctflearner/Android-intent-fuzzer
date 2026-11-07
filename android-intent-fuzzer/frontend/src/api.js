const BASE = '/api';

async function request(path, opts = {}) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    ...opts,
    headers: {
      ...(opts.body && !(opts.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}),
      ...opts.headers,
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  if (ct.includes('text/html')) return res.text();
  return res.json().catch(() => res.text());
}

export const api = {
  // Scans
  listScans: () => request('/scans'),
  createScan: (formData) => request('/scans', { method: 'POST', body: formData }),
  getScan: (id) => request(`/scans/${id}`),
  startScan: (id) => request(`/scans/${id}/start`, { method: 'POST' }),
  cancelScan: (id) => request(`/scans/${id}/cancel`, { method: 'POST' }),
  getFindings: (id) => request(`/scans/${id}/findings`),
  getFinding: (id, fid) => request(`/scans/${id}/findings/${fid}`),
  getStatic: (id) => request(`/scans/${id}/static`),
  getChains: (id) => request(`/scans/${id}/chains`),
  getReport: (id, format = 'html') =>
    fetch(`${BASE}/scans/${id}/report?format=${format}`).then((r) => {
      if (!r.ok) throw new Error(`${r.status}`);
      return r.text();
    }),

  // Devices
  listDevices: () => request('/devices'),
  createEmulator: () => request('/devices/emulator', { method: 'POST' }),

  // Plugins
  listPlugins: () => request('/plugins'),
};

export function connectWebSocket(scanId, onMessage, onClose) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  const ws = new WebSocket(`${proto}//${host}/ws/scan/${scanId}`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch {
      onMessage({ type: 'raw', data: event.data });
    }
  };

  ws.onclose = () => {
    if (onClose) onClose();
  };

  ws.onerror = (err) => {
    console.error('WebSocket error:', err);
  };

  return ws;
}
