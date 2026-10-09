import React, { createContext, useContext, useState, useEffect } from 'react';
import { THEME_DARK, THEME_LIGHT } from '../constants/theme';
import { storageService } from '../services/storageService';

const THEME_STORAGE_KEY = 'cyberguard_theme_mode_v2';

const ThemeContext = createContext({
  theme: 'dark',
  isDark: true,
  colors: THEME_DARK,
  toggleTheme: () => {},
  setTheme: () => {}
});

export function ThemeProvider({ children }) {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    // Default to dark mode strictly
    storageService.getItem(THEME_STORAGE_KEY).then((stored) => {
      if (stored === 'light') {
        setIsDark(false);
      } else {
        setIsDark(true);
      }
    }).catch(() => {
      setIsDark(true);
    });
  }, []);

  const toggleTheme = () => {
    setIsDark((prev) => {
      const next = !prev;
      const mode = next ? 'dark' : 'light';
      storageService.setItem(THEME_STORAGE_KEY, mode).catch(() => {});
      return next;
    });
  };

  const setTheme = (mode) => {
    const dark = mode === 'dark';
    setIsDark(dark);
    storageService.setItem(THEME_STORAGE_KEY, mode).catch(() => {});
  };

  const activeColors = isDark ? THEME_DARK : THEME_LIGHT;

  return (
    <ThemeContext.Provider
      value={{
        theme: isDark ? 'dark' : 'light',
        isDark,
        colors: activeColors,
        toggleTheme,
        setTheme
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    return {
      theme: 'dark',
      isDark: true,
      colors: THEME_DARK,
      toggleTheme: () => {},
      setTheme: () => {}
    };
  }
  return context;
}
