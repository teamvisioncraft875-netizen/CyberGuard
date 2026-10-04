import React, { useState, useEffect } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider, useToast } from './hooks/useToast';
import { AuthProvider } from './context/AuthContext';
import { AppRoutes } from './pages/AppRoutes';
import { Drawer, RiskBadge, Button } from './components/ui';
import { normalizeRisk } from './utils/risk';

function MainApp() {
  const [selectedIncident, setSelectedIncident] = useState(null);
  const { addToast } = useToast();

  // Global ⌘K listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        addToast({
          type: 'info',
          title: 'Quick Command Launcher',
          message: 'Type to navigate: "Scan Center", "Incident Triage", or "Guardian Mode".',
        });
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [addToast]);

  return (
    <>
      <AppRoutes
        onSelectIncident={(inc) => setSelectedIncident(inc)}
        onTriggerAlert={(alert) => addToast(alert)}
        onSearchFocus={() =>
          addToast({
            type: 'info',
            title: 'Search',
            message: 'Search incidents by keyword or ID.',
          })
        }
      />

      {/* Global Quick Incident Inspection Drawer */}
      <Drawer
        isOpen={Boolean(selectedIncident)}
        onClose={() => setSelectedIncident(null)}
        title="Incident Detail"
        width="w-full max-w-xl"
      >
        {selectedIncident && (
          <div className="space-y-6 font-mono text-xs">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <RiskBadge level={normalizeRisk(selectedIncident.risk_level)} />
                <span className="text-muted-foreground uppercase text-[10px]">
                  Status: <strong className="text-foreground capitalize">{selectedIncident.status}</strong>
                </span>
              </div>
              <h2 className="font-headline text-base font-bold text-foreground font-sans">
                {selectedIncident.explanation}
              </h2>
            </div>

            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-muted/40 border border-border">
              <div>
                <span className="text-[10px] text-muted-foreground uppercase block">Incident ID</span>
                <span className="text-foreground text-[11px] select-all font-mono">{selectedIncident.id}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase block">Threat Type</span>
                <span className="text-foreground text-[11px] capitalize">{selectedIncident.threat_type}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase block">Source Type</span>
                <span className="text-foreground text-[11px] uppercase font-mono">{selectedIncident.source_type}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted-foreground uppercase block">Reported</span>
                <span className="text-foreground text-[11px]">{selectedIncident.timeAgo || selectedIncident.created_at}</span>
              </div>
            </div>

            <div className="flex justify-end pt-4 border-t border-border">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedIncident(null)}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Drawer>
    </>
  );
}

export default function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="cyberguard-theme">
      <ToastProvider>
        <AuthProvider>
          <BrowserRouter>
            <MainApp />
          </BrowserRouter>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}
