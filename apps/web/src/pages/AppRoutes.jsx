import React from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import {
  DashboardPage,
  ScanCenterPage,
  IncidentsPage,
  GuardianPage,
  SettingsPage,
  DesignSystemPage,
} from './index';
import { LoginPage } from './LoginPage';
import { SignupPage } from './SignupPage';
import { ProtectedRoute } from '../context/AuthContext';
import { AppLayout } from '../layouts/AppLayout';

export const ROUTES = Object.freeze({
  DASHBOARD: '/',
  SCAN_CENTER: '/scan-center',
  INCIDENTS: '/incidents',
  GUARDIAN: '/guardian',
  SETTINGS: '/settings',
  DESIGN_SYSTEM: '/design-system',
  LOGIN: '/login',
  SIGNUP: '/signup',
});

/**
 * AppRoutes component provides declarative URL routing for CyberGuard Web using react-router-dom.
 */
export function AppRoutes({
  onSelectIncident,
  onTriggerAlert,
  onSearchFocus,
}) {
  const navigate = useNavigate();

  return (
    <Routes>
      {/* 1. Public Authentication Routes */}
      <Route
        path="/login"
        element={
          <LoginPage
            onLoginSuccess={() => navigate('/')}
            onNavigateSignup={() => navigate('/signup')}
          />
        }
      />
      <Route
        path="/signup"
        element={
          <SignupPage
            onSignupSuccess={() => navigate('/')}
            onNavigateLogin={() => navigate('/login')}
          />
        }
      />

      {/* 2. Protected Application Routes (wrapped in ProtectedRoute and AppLayout) */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <DashboardPage
                onSelectIncident={onSelectIncident}
                onNavigateScan={() => navigate('/scan-center')}
              />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/scan-center"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <ScanCenterPage onTriggerAlert={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/incidents"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <IncidentsPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/guardian"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <GuardianPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <SettingsPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/design-system"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <DesignSystemPage />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      {/* 3. Fallback Route */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default AppRoutes;
