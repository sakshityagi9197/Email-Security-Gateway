import { Suspense, lazy } from 'react';
import { Route, Routes, Navigate } from 'react-router-dom';

import { AuthProvider } from './context/AuthContext.jsx';
import { ToastProvider } from './context/ToastContext.jsx';
import { PageProvider } from './context/PageContext.jsx';

import Layout from './components/Layout.jsx';
import RequireAuth from './components/RequireAuth.jsx';

const LandingPage = lazy(() => import('./pages/LandingPage.jsx'));
const LoginPage = lazy(() => import('./pages/LoginPage.jsx'));
const DashboardPage = lazy(() => import('./pages/DashboardPage.jsx'));
const PoliciesPage = lazy(() => import('./pages/PoliciesPage.jsx'));
const PolicyDetailPage = lazy(() => import('./pages/PolicyDetailPage.jsx'));
const EmailsPage = lazy(() => import('./pages/EmailsPage.jsx'));
const EmailDetailPage = lazy(() => import('./pages/EmailDetailPage.jsx'));
const SettingsPage = lazy(() => import('./pages/SettingsPage.jsx'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage.jsx'));

const SuspenseFallback = (
  <div className="text-muted p-3">
    Loading...
  </div>
);

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <PageProvider>
          <Suspense fallback={SuspenseFallback}>
            <Routes>
              <Route element={<Layout />}>
                <Route index element={<LandingPage />} />
                <Route path="login" element={<LoginPage />} />

                <Route element={<RequireAuth />}>
                  <Route path="dashboard" element={<DashboardPage />} />
                  <Route path="policies" element={<PoliciesPage />} />
                  <Route path="policies/:id" element={<PolicyDetailPage />} />
                  <Route path="policy/:id" element={<PolicyDetailPage />} />
                  <Route path="emails" element={<EmailsPage />} />
                  <Route path="emails/:id" element={<EmailDetailPage />} />
                  <Route path="settings" element={<SettingsPage />} />
                </Route>

                <Route path="policy" element={<Navigate to="/policies" replace />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </Suspense>
        </PageProvider>
      </ToastProvider>
    </AuthProvider>
  );
}