import { AuthProvider } from "./context/AuthContext";
import { NavigationProvider, useNavigation } from "./context/NavigationContext";
import { AppLayout } from "./layouts/AppLayout";

import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { NewScanPage } from "./pages/NewScanPage";
import { LiveScanProgressPage } from "./pages/LiveScanProgressPage";
import { ScanResultsPage } from "./pages/ScanResultsPage";
import { FindingsListPage } from "./pages/FindingsListPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { RemediationCenterPage } from "./pages/RemediationCenterPage";
import { FixVerificationHistoryPage } from "./pages/FixVerificationHistoryPage";
import { ScanHistoryPage } from "./pages/ScanHistoryPage";
import { ReportsPage } from "./pages/ReportsPage";
import { SettingsPage } from "./pages/SettingsPage";

function AppContent() {
  const { currentRoute } = useNavigation();

  function renderPage() {
    switch (currentRoute) {
      case "landing":
        return <LandingPage />;
      case "login":
        return <LoginPage />;
      case "dashboard":
        return <DashboardPage />;
      case "new-scan":
        return <NewScanPage />;
      case "live-scan":
        return <LiveScanProgressPage />;
      case "scan-results":
        return <ScanResultsPage />;
      case "findings":
        return <FindingsListPage />;
      case "finding-detail":
        return <FindingDetailPage />;
      case "remediation-center":
        return <RemediationCenterPage />;
      case "verification-history":
        return <FixVerificationHistoryPage />;
      case "scan-history":
        return <ScanHistoryPage />;
      case "reports":
        return <ReportsPage />;
      case "settings":
        return <SettingsPage />;
      default:
        return <DashboardPage />;
    }
  }

  return <AppLayout>{renderPage()}</AppLayout>;
}

export function App() {
  return (
    <AuthProvider>
      <NavigationProvider>
        <AppContent />
      </NavigationProvider>
    </AuthProvider>
  );
}

export default App;
