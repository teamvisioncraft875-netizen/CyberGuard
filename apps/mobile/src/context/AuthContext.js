import React, { createContext, useState, useEffect, useCallback } from 'react';
import { authService } from '../services/authService';
import { setUnauthorizedHandler } from '../services/apiClient';

export const AuthContext = createContext({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  login: async () => {},
  signup: async () => {},
  logout: async () => {},
  clearError: () => {}
});

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const handleLogout = useCallback(async () => {
    setIsLoading(true);
    try {
      await authService.logout();
    } finally {
      setUser(null);
      setIsAuthenticated(false);
      setIsLoading(false);
    }
  }, []);

  // Initialize session on startup
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      setIsAuthenticated(false);
    });

    async function checkAuth() {
      try {
        const session = await authService.getStoredSession();
        if (session.token) {
          try {
            const me = await authService.getMe();
            setUser(me || session.user);
            setIsAuthenticated(true);
          } catch {
            // If getMe fails and session was invalid
            if (session.user) {
              setUser(session.user);
              setIsAuthenticated(true);
            }
          }
        }
      } catch (err) {
        console.warn('[AuthContext.checkAuth]', err.message);
      } finally {
        setIsLoading(false);
      }
    }

    checkAuth();
  }, []);

  const login = async (email, password) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await authService.login(email, password);
      setUser(res.user);
      setIsAuthenticated(true);
      return res;
    } catch (err) {
      setError(err.message || 'Login failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (email, password, role, orgName) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await authService.signup(email, password, role, orgName);
      setUser(res.user);
      setIsAuthenticated(true);
      return res;
    } catch (err) {
      setError(err.message || 'Signup failed');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const clearError = () => setError(null);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        error,
        login,
        signup,
        logout: handleLogout,
        clearError
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
