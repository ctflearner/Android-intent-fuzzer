import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import ScanMonitor from './pages/ScanMonitor';
import AttackSurface from './pages/AttackSurface';
import Findings from './pages/Findings';
import Explorer from './pages/Explorer';
import AttackGraph from './pages/AttackGraph';
import Report from './pages/Report';

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="upload" element={<Upload />} />
        <Route path="scan/:scanId" element={<ScanMonitor />} />
        <Route path="scan/:scanId/surface" element={<AttackSurface />} />
        <Route path="findings" element={<Findings />} />
        <Route path="scan/:scanId/findings" element={<Findings />} />
        <Route path="explorer" element={<Explorer />} />
        <Route path="scan/:scanId/explorer" element={<Explorer />} />
        <Route path="attack-graph" element={<AttackGraph />} />
        <Route path="scan/:scanId/chains" element={<AttackGraph />} />
        <Route path="report" element={<Report />} />
        <Route path="scan/:scanId/report" element={<Report />} />
      </Route>
    </Routes>
  );
}
