import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import UrlScannerPage from './pages/UrlScannerPage.jsx';
import WebsiteAnalyzerPage from './pages/WebsiteAnalyzerPage.jsx';
import EmailAnalyzerPage from './pages/EmailAnalyzerPage.jsx';
import ScreenshotAnalyzerPage from './pages/ScreenshotAnalyzerPage.jsx';
import ThreatIntelPage from './pages/ThreatIntelPage.jsx';
import ScanHistoryPage from './pages/ScanHistoryPage.jsx';
import InvestigationPage from './pages/InvestigationPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="scanner/url" element={<UrlScannerPage />} />
          <Route path="scanner/website" element={<WebsiteAnalyzerPage />} />
          <Route path="scanner/email" element={<EmailAnalyzerPage />} />
          <Route path="scanner/screenshot" element={<ScreenshotAnalyzerPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="history" element={<ScanHistoryPage />} />
          <Route path="investigation/:id" element={<InvestigationPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
