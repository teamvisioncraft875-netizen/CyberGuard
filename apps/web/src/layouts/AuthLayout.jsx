import React from 'react';
import { cn } from '../utils/cn';
import { ShieldCheck, Lock } from 'lucide-react';
import { ThemeToggle } from '../components/ui/ThemeToggle';

export function AuthLayout({
  children,
  title = 'Command Gateway Access',
  subtitle = 'Authenticate to access operational security logs and threat triage',
}) {
  return (
    <div className="min-h-[100dvh] bg-background text-foreground flex flex-col justify-center items-center p-4 sm:p-6 relative overflow-hidden transition-colors duration-200">
      {/* Top right Theme Toggle */}
      <div className="absolute top-4 right-4 z-20">
        <ThemeToggle variant="outline" size="sm" />
      </div>

      <div className="max-w-md w-full relative z-10">
        {/* Header Branding */}
        <div className="text-center mb-8 flex flex-col items-center">
          <div className="p-3.5 rounded-2xl bg-primary/10 border border-primary/20 text-primary mb-4">
            <ShieldCheck className="w-9 h-9" />
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground flex items-center gap-2 font-headline">
            CYBERGUARD
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-1.5 max-w-xs leading-relaxed">
            {subtitle}
          </p>
        </div>

        {/* Card Surface */}
        <div className="rounded-2xl bg-card border border-border shadow-xl backdrop-blur-xl p-6 sm:p-8">
          <div className="mb-6 pb-4 border-b border-border flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-primary" />
              {title}
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground">
              TLS 1.3 ENC
            </span>
          </div>

          {children}
        </div>

        {/* Footer info */}
        <div className="mt-8 text-center text-xs text-muted-foreground font-mono">
          Protected by Row Level Security & Isolation Forest Threat Engines
        </div>
      </div>
    </div>
  );
}
