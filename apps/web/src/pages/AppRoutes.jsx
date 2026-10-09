import React from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import {
  DashboardPage,
  ScanCenterPage,
  IncidentsPage,
  GuardianPage,
  SettingsPage,
  DesignSystemPage,
  AttackSurfacePage,
  FirewallPage,
  AgentsPage,
  DDoSPage,
} from './index';
import { LoginPage } from './LoginPage';
import { SignupPage } from './SignupPage';
import LandingPage from './LandingPage';
import { ProtectedRoute } from '../context/AuthContext';
import { AppLayout } from '../layouts/AppLayout';


export const ROUTES = Object.freeze({
  HOME: '/',
  LANDING: '/landing',
  DASHBOARD: '/dashboard',
  SCAN_CENTER: '/scan-center',
  INCIDENTS: '/incidents',
  ATTACK_SURFACE: '/attack-surface',
  RESPONSE_ACTIONS: '/response-actions',
  SCANS: '/scans',
  FIREWALL: '/firewall',
  AGENTS: '/agents',
  DDOS: '/ddos',
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
      {/* 0. Public Landing Page at Root */}
      <Route path="/" element={<LandingPage />} />
      <Route path="/landing" element={<LandingPage />} />

      {/* 1. Public Authentication Routes */}
      <Route
        path="/login"
        element={
          <LoginPage
            onLoginSuccess={() => navigate('/dashboard')}
            onNavigateSignup={() => navigate('/signup')}
          />
        }
      />
      <Route
        path="/signup"
        element={
          <SignupPage
            onSignupSuccess={() => navigate('/dashboard')}
            onNavigateLogin={() => navigate('/login')}
          />
        }
      />

      {/* 2. Protected Dashboard Route */}
      <Route
        path="/dashboard"
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
        path="/pages/security/incidents"
        element={
          <ProtectedRoute>
            <AppLayout onSearchFocus={onSearchFocus}>
              <IncidentsPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      {/* Attack Surface Discovery & SOC Workflow Routes */}
      <Route
        path="/attack-surface"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="overview" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/pages/security/attack-surface"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="overview" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/response-actions"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="response-actions" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/pages/security/response-actions"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="response-actions" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/scans"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="scans" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/pages/security/scans"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AttackSurfacePage initialTab="scans" onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/firewall"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <FirewallPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/agents"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AgentsPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/pages/security/agents"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <AgentsPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />

      <Route
        path="/ddos"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <DDoSPage onTriggerToast={onTriggerAlert} />
            </AppLayout>
          </ProtectedRoute>
        }
      />
      <Route
        path="/pages/security/ddos"
        element={
          <ProtectedRoute requiredRole="admin">
            <AppLayout onSearchFocus={onSearchFocus}>
              <DDoSPage onTriggerToast={onTriggerAlert} />
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
