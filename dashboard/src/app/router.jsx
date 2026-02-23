import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { LoginPage } from "../features/auth/LoginPage";
import { RegisterPage } from "../features/auth/RegisterPage";
import { RequireAuth } from "../features/auth/RequireAuth";
import { DashboardHomePage } from "../features/dashboard/DashboardHomePage";
import { UpgradePage } from "../features/upgrade/UpgradePage";
import { AppShell } from "../shared/layout/AppShell";
import { useDashboardData } from "../hooks/useDashboardData";

function resolveHealthStatus(healthQuery) {
  if (healthQuery.isLoading) return "checking";
  if (healthQuery.isError) return "offline";
  return "online";
}

function ProtectedShell() {
  const { isAuthenticated, logout } = useAuth();
  const data = useDashboardData(isAuthenticated);
  const user = data.meQuery.data;

  return (
    <RequireAuth>
      <AppShell
        isAuthenticated={isAuthenticated}
        username={user?.username}
        apiHealth={resolveHealthStatus(data.health)}
        onLogout={logout}
      >
        <Outlet />
      </AppShell>
    </RequireAuth>
  );
}

function AuthOnly({ children }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }
  return children;
}

export function AppRouter() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route
          path="/login"
          element={
            <AuthOnly>
              <LoginPage />
            </AuthOnly>
          }
        />
        <Route
          path="/register"
          element={
            <AuthOnly>
              <RegisterPage />
            </AuthOnly>
          }
        />

        <Route element={<ProtectedShell />}>
          <Route path="/" element={<DashboardHomePage />} />
          <Route path="/upgrade" element={<UpgradePage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
