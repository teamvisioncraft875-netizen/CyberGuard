import * as React from 'react';
import { useTheme } from '../../hooks/useTheme';
import { Button } from './Button';
import { Sun, Moon } from 'lucide-react';

export function ThemeToggle({ className, size = 'sm', variant = 'ghost' }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <Button
      variant={variant}
      size={size}
      onClick={toggleTheme}
      className={className}
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      title={`Current: ${isDark ? 'Dark' : 'Light'} Mode. Click to switch.`}
    >
      {isDark ? (
        <Sun className="h-4 w-4 text-amber-400 transition-transform hover:rotate-45" />
      ) : (
        <Moon className="h-4 w-4 text-slate-700 transition-transform hover:-rotate-12" />
      )}
      <span className="sr-only">Toggle theme</span>
    </Button>
  );
}
