import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authService } from '../services/authService';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => authService.getToken());
  const [user, setUser] = useState(() => authService.getCurrentUser());
  const [loading, setLoading] = useState(false);

  // Synchronize on mount and handle global unauthorized events
  useEffect(() => {
    const handleUnauthorized = () => {
      setToken(null);
      setUser(null);
    };

    window.addEventListener('cyberguard:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('cyberguard:unauthorized', handleUnauthorized);
  }, []);

  const login = useCallback(async (email, password) => {
    setLoading(true);
    try {
      const res = await authService.login(email, password);
      setToken(res?.token || res?.accessToken || null);
      setUser(res?.user || null);
      return res;
    } finally {
      setLoading(false);
    }
  }, []);

  const signup = useCallback(async (email, password, fullName, role = 'individual', organizationName = undefined) => {
    setLoading(true);
    try {
      const res = await authService.signup(email, password, fullName, role, organizationName);
      setToken(res?.token || res?.accessToken || null);
      setUser(res?.user || null);
      return res;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await authService.logout();
    setToken(null);
    setUser(null);
  }, []);

  const value = {
    user,
    token,
    loading,
    isAuthenticated: Boolean(token),
    login,
    signup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

import { Navigate, useLocation } from 'react-router-dom';

export function ProtectedRoute({ children, fallback = null, onUnauthorized }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      onUnauthorized?.();
    }
  }, [isAuthenticated, loading, onUnauthorized]);

  if (loading) {
    return fallback;
  }

  if (!isAuthenticated) {
    return fallback || <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
