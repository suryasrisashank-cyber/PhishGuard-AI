import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import UrlScannerPage from './pages/UrlScannerPage.jsx';
import WebsiteAnalyzerPage from './pages/WebsiteAnalyzerPage.jsx';
import EmailAnalyzerPage from './pages/EmailAnalyzerPage.jsx';
import FileAnalyzerPage from './pages/FileAnalyzerPage.jsx';
import PcapAnalyzerPage from './pages/PcapAnalyzerPage.jsx';
import ScreenshotAnalyzerPage from './pages/ScreenshotAnalyzerPage.jsx';
import ThreatIntelPage from './pages/ThreatIntelPage.jsx';
import IntegrationsDiagnosticsPage from './pages/IntegrationsDiagnosticsPage.jsx';
import IocExplorerPage from './pages/IocExplorerPage.jsx';
import AlertsPage from './pages/AlertsPage.jsx';
import CampaignsPage from './pages/CampaignsPage.jsx';
import InvestigationPage from './pages/InvestigationPage.jsx';
import MitreAttackPage from './pages/MitreAttackPage.jsx';
import SplunkPage from './pages/SplunkPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import ScanHistoryPage from './pages/ScanHistoryPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';
import { BackendStatusProvider } from './context/BackendStatusContext.jsx';
import ErrorBoundary from './components/ErrorBoundary.jsx';

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <BackendStatusProvider>
          <Routes>
            <Route path="/" element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="scanner/url" element={<UrlScannerPage />} />
          <Route path="scanner/website" element={<WebsiteAnalyzerPage />} />
          <Route path="scanner/email" element={<EmailAnalyzerPage />} />
          <Route path="scanner/file" element={<FileAnalyzerPage />} />
          <Route path="scanner/pcap" element={<PcapAnalyzerPage />} />
          <Route path="scanner/screenshot" element={<ScreenshotAnalyzerPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route path="system/integrations" element={<IntegrationsDiagnosticsPage />} />
          <Route path="diagnostics" element={<IntegrationsDiagnosticsPage />} />
          <Route path="integrations" element={<IntegrationsDiagnosticsPage />} />
          <Route path="system/diagnostics" element={<IntegrationsDiagnosticsPage />} />
          <Route path="iocs" element={<IocExplorerPage />} />
          <Route path="campaigns" element={<CampaignsPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="investigations" element={<AlertsPage />} />
          <Route path="investigations/:id" element={<InvestigationPage />} />
          <Route path="investigation/:id" element={<InvestigationPage />} />
          <Route path="mitre" element={<MitreAttackPage />} />
          <Route path="splunk" element={<SplunkPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="history" element={<ScanHistoryPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
        </Routes>
        </BackendStatusProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
