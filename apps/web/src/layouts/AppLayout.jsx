import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { cn } from '../utils/cn';
import {
  ShieldAlert,
  LayoutDashboard,
  Radar,
  AlertTriangle,
  Sliders,
  Menu,
  X,
  Search,
  Bell,
  HelpCircle,
  Crosshair,
  ShieldCheck,
  Flame,
  Bot,
  Zap,
} from 'lucide-react';
import { ThemeToggle } from '../components/ui/ThemeToggle';
import { useSocket } from '../hooks/useSocket';
import { normalizeRisk } from '../utils/risk';
import { formatRelativeTime } from '../utils/format';
import { analyticsService } from '../services';

export function AppLayout({
  children,
  activeNav: activeNavProp,
  onNavChange,
  socketConnected = true,
  onSearchFocus,
}) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout, isAdmin } = useAuth();
  const { unreadAlertsCount, resetUnreadCount, liveAlerts, isConnected, onIncident } = useSocket();

  const [activeThreatCount, setActiveThreatCount] = useState(null);

  // Fetch real-time active threat count for the Incidents badge
  useEffect(() => {
    let isMounted = true;
    if (!user) {
      setActiveThreatCount(null);
      return;
    }

    analyticsService
      .getOverview()
      .then((data) => {
        if (isMounted && typeof data?.active_threats === 'number') {
          setActiveThreatCount(data.active_threats);
        }
      })
      .catch((_err) => {
        // Safe fallback: leave as null so no fake or misleading badge displays
        if (isMounted) {
          setActiveThreatCount(null);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [user]);

  // Dynamically update active threats count when live socket incidents arrive
  useEffect(() => {
    if (!onIncident) return;
    const unsubscribe = onIncident((incident) => {
      if (!incident || incident.status === 'resolved') return;
      setActiveThreatCount((prev) => (prev != null ? prev + 1 : 1));
    });
    return unsubscribe;
  }, [onIncident]);

  // Compute incident badge text (null if 0 or unavailable)
  const incidentBadge = useMemo(() => {
    if (activeThreatCount == null || activeThreatCount <= 0) return null;
    return activeThreatCount > 99 ? '99+' : String(activeThreatCount);
  }, [activeThreatCount]);

  // Compute dynamic user initials and display name gracefully from authenticated session
  const displayName = user?.full_name?.trim() || user?.email?.split('@')[0] || 'Security Analyst';
  const roleDisplay = user?.role ? user.role.replace(/_/g, ' ') : 'Security Analyst';
  const initials = (() => {
    if (user?.full_name?.trim()) {
      const parts = user.full_name.trim().split(/\s+/).filter(Boolean);
      if (parts.length >= 2) {
        return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      }
      if (parts.length === 1 && parts[0].length >= 2) {
        return parts[0].slice(0, 2).toUpperCase();
      }
      if (parts.length === 1) {
        return parts[0][0].toUpperCase();
      }
    }
    if (user?.email?.trim()) {
      const namePart = user.email.split('@')[0];
      return namePart.slice(0, 2).toUpperCase();
    }
    return 'SA';
  })();

  const navigationItems = useMemo(() => {
    const items = [
      { id: 'dashboard', path: '/', label: 'Dashboard', icon: LayoutDashboard },
      {
        id: 'attack-surface',
        path: '/attack-surface',
        label: 'Attack Surface',
        icon: Crosshair,
        adminOnly: true,
        badge: 'Live',
        badgeColor: 'bg-amber-500/15 text-amber-500 border border-amber-500/30',
      },
      { id: 'scan-center', path: '/scan-center', label: 'Scan Center', icon: Radar },
      {
        id: 'incidents',
        path: '/incidents',
        label: 'Incidents',
        icon: AlertTriangle,
        badge: incidentBadge,
        badgeColor: 'bg-destructive/15 text-destructive border border-destructive/30',
      },
      {
        id: 'firewall',
        path: '/firewall',
        label: 'Firewall',
        icon: Flame,
        adminOnly: true,
      },
      {
        id: 'agents',
        path: '/agents',
        label: 'Agent Fleet',
        icon: Bot,
        adminOnly: true,
      },
      {
        id: 'ddos',
        path: '/ddos',
        label: 'DDoS Monitor',
        icon: Zap,
        adminOnly: true,
      },
      { id: 'guardian', path: '/guardian', label: 'Guardian Mode', icon: ShieldCheck },
      { id: 'settings', path: '/settings', label: 'Settings', icon: Sliders },
    ];

    return items.filter((item) => !item.adminOnly || isAdmin);
  }, [isAdmin, incidentBadge]);

  const handleNavClick = (itemOrId) => {
    let id = typeof itemOrId === 'string' ? itemOrId : itemOrId.id;
    let path = typeof itemOrId === 'string'
      ? (navigationItems.find((i) => i.id === itemOrId)?.path || (itemOrId === 'dashboard' ? '/' : `/${itemOrId}`))
      : itemOrId.path;

    if ((id === 'attack-surface' || id === 'firewall' || id === 'agents' || id === 'ddos') && !isAdmin) {
      return;
    }

    onNavChange?.(id);
    if (path) {
      navigate(path);
    }
    setMobileMenuOpen(false);
  };

  const isItemActive = (item) => {
    if (activeNavProp && activeNavProp !== 'auto') {
      return activeNavProp === item.id;
    }
    if (item.path === '/') {
      return location.pathname === '/' || location.pathname === '';
    }
    return location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-sans transition-colors duration-200 selection:bg-primary selection:text-primary-foreground">
      {/* 1. FIXED TOP HEADER BAR */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-surface-lowest/90 backdrop-blur-xl border-b border-border z-50 flex items-center justify-between px-4 lg:px-8">
        {/* Brand Emblem */}
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted"
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <div
            className="flex items-center gap-2.5 cursor-pointer"
            onClick={() => handleNavClick('dashboard')}
          >
            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center text-primary">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <span className="font-headline text-lg font-bold tracking-tight text-foreground">
              CyberGuard
            </span>
          </div>
        </div>

        {/* Global Search Bar with ⌘K */}
        <div className="flex-1 max-w-md mx-6 hidden md:block">
          <div className="relative flex items-center">
            <Search className="w-4 h-4 text-muted-foreground absolute left-3 pointer-events-none" />
            <input
              type="text"
              placeholder="Search incidents, indicators, users..."
              onFocus={onSearchFocus}
              className="w-full h-9 pl-9 pr-12 rounded-lg bg-surface-low border border-border font-body text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
            />
            <kbd className="absolute right-2.5 font-mono text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded border border-border">
              ⌘K
            </kbd>
          </div>
        </div>

        {/* Right Status Indicators, Theme Toggle & User Profile */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Theme Toggle (Sun/Moon Switcher) */}
          <ThemeToggle variant="ghost" size="sm" />

          {/* Notifications Button */}
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                const nextOpen = !notificationsOpen;
                setNotificationsOpen(nextOpen);
                if (nextOpen && unreadAlertsCount > 0) {
                  resetUnreadCount();
                }
              }}
              className="relative p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
              aria-label="Alerts"
            >
              <Bell className="w-5 h-5" />
              {unreadAlertsCount > 0 && (
                <span className="absolute top-1 right-1 flex items-center justify-center h-4 min-w-[1rem] px-1 bg-destructive text-destructive-foreground border border-destructive/50 rounded-full font-mono text-[9px] font-bold animate-pulse">
                  {unreadAlertsCount > 99 ? '99+' : unreadAlertsCount}
                </span>
              )}
            </button>

            {/* Notification Popover */}
            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-[calc(100vw-2rem)] max-w-sm sm:w-80 rounded-xl bg-card border border-border p-4 shadow-2xl z-50 space-y-3 font-sans text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-border">
                  <div className="flex items-center gap-2">
                    <span className="font-headline font-bold text-foreground">
                      Live Alerts ({liveAlerts.length})
                    </span>
                    <span
                      className={cn(
                        'w-2 h-2 rounded-full',
                        isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-muted-foreground/50'
                      )}
                      title={isConnected ? 'Real-time WebSocket active' : 'WebSocket standby'}
                    />
                  </div>
                  {liveAlerts.length > 0 && (
                    <button
                      type="button"
                      onClick={resetUnreadCount}
                      className="font-mono text-[10px] text-primary hover:underline"
                    >
                      Clear Badge
                    </button>
                  )}
                </div>
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {liveAlerts.length === 0 ? (
                    <div className="py-6 text-center text-muted-foreground space-y-1">
                      <p className="font-medium text-xs text-foreground/80">No incoming alerts yet</p>
                      <p className="text-[11px] text-muted-foreground">
                        {isConnected
                          ? 'Real-time incident stream connected.'
                          : 'Connecting to threat telemetry stream...'}
                      </p>
                    </div>
                  ) : (
                    liveAlerts.map((alert) => {
                      const norm = normalizeRisk(alert.risk_level);
                      return (
                        <div
                          key={alert.id}
                          onClick={() => {
                            setNotificationsOpen(false);
                            navigate('/incidents');
                          }}
                          className={cn(
                            'p-2.5 rounded-lg bg-muted/60 border cursor-pointer hover:bg-muted transition-colors space-y-1',
                            norm === 'critical'
                              ? 'border-destructive/50'
                              : norm === 'high'
                              ? 'border-amber-500/50'
                              : 'border-border'
                          )}
                        >
                          <div className="flex items-center justify-between">
                            <span
                              className={cn(
                                'font-semibold capitalize text-xs',
                                norm === 'critical'
                                  ? 'text-destructive'
                                  : norm === 'high'
                                  ? 'text-amber-500'
                                  : 'text-primary'
                              )}
                            >
                              {norm}: {alert.threat_type?.replace(/_/g, ' ') || 'Threat Event'}
                            </span>
                            <span className="text-[10px] font-mono text-muted-foreground">
                              {formatRelativeTime(alert.created_at)}
                            </span>
                          </div>
                          <p className="text-muted-foreground text-[11px] line-clamp-2 leading-relaxed">
                            {alert.explanation || 'Anomaly reported'}
                          </p>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="h-6 w-px bg-border hidden sm:block"></div>

          {/* Real User Profile Bound to useAuth() */}
          <div
            className="flex items-center gap-2.5 cursor-pointer group"
            onClick={() => handleNavClick({ id: 'settings', path: '/settings' })}
            title="Click to view Settings"
          >
            <div className="relative">
              <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-500 border border-border flex items-center justify-center text-white font-mono text-xs font-bold shadow-inner">
                {initials}
              </div>
              <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-emerald-500 ring-2 ring-background"></span>
            </div>
            <div className="hidden xl:flex flex-col text-left">
              <span className="font-body text-xs font-semibold text-foreground leading-tight">
                {displayName}
              </span>
              <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground leading-tight capitalize">
                {roleDisplay}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* 2. FIXED SIDEBAR NAVIGATION */}
      <aside className="fixed left-0 top-16 bottom-0 w-64 bg-surface-lowest border-r border-border z-40 hidden lg:flex flex-col justify-between p-4 select-none">
        <div className="space-y-4">
          <div className="px-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Navigation
          </div>

          <nav className="space-y-1">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = isItemActive(item);

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNavClick(item)}
                  className={cn(
                    'w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all duration-150',
                    isActive
                      ? 'bg-muted text-primary font-bold border-l-2 border-primary shadow-sm'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/60'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={cn('w-4 h-4', isActive ? 'text-primary' : 'text-muted-foreground')} />
                    <span>{item.label}</span>
                  </div>

                  {item.badge && (
                    <span
                      className={cn(
                        'font-mono text-[10px] px-1.5 py-0.5 rounded font-semibold tracking-wide',
                        item.badgeColor || 'bg-muted text-muted-foreground'
                      )}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="space-y-3 pt-4 border-t border-border">
          <button
            type="button"
            onClick={() => handleNavClick({ id: 'design-system', path: '/design-system' })}
            className={cn(
              'flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs font-body transition-colors w-full text-left',
              location.pathname === '/design-system'
                ? 'bg-muted text-primary font-medium'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
            )}
          >
            <ShieldAlert className="w-4 h-4 text-primary" />
            <span>UI Design System</span>
          </button>

          <div className="space-y-1.5 px-2 text-[11px] font-mono text-muted-foreground">
            <div className="flex items-center justify-between">
              <span>API Gateway</span>
              <span className="flex items-center gap-1.5 text-emerald-500 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Connected
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Live Feed</span>
              <span
                className={cn(
                  'flex items-center gap-1.5 font-medium',
                  isConnected ? 'text-emerald-500' : 'text-muted-foreground'
                )}
              >
                <span
                  className={cn(
                    'w-1.5 h-1.5 rounded-full',
                    isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-muted-foreground/40'
                  )}
                />
                {isConnected ? 'Active' : 'Offline'}
              </span>
            </div>
          </div>

          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-2 py-1.5 text-muted-foreground hover:text-foreground text-xs font-body transition-colors"
          >
            <HelpCircle className="w-4 h-4" />
            <span>Documentation</span>
          </a>
        </div>
      </aside>

      {/* Mobile Drawer Navigation */}
      {mobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-md pt-20 px-6 space-y-4">
          <div className="flex justify-between items-center pb-4 border-b border-border">
            <span className="font-headline font-bold text-foreground">Navigation</span>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              className="p-1 rounded text-muted-foreground hover:text-foreground"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
          <div className="space-y-2">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = isItemActive(item);
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNavClick(item)}
                  className={cn(
                    'w-full flex items-center justify-between p-3 rounded-lg text-sm font-medium',
                    isActive ? 'bg-primary text-primary-foreground font-bold' : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && <span className="text-xs font-mono">{item.badge}</span>}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => handleNavClick({ id: 'design-system', path: '/design-system' })}
              className={cn(
                'w-full flex items-center justify-between p-3 rounded-lg text-sm font-medium',
                location.pathname === '/design-system' ? 'bg-primary text-primary-foreground font-bold' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-5 h-5" />
                <span>UI Design System</span>
              </div>
            </button>
          </div>
        </div>
      )}

      {/* 3. MAIN CONTENT VIEWPORT */}
      <div className="lg:pl-64 pt-16 min-h-screen flex flex-col flex-1 bg-background">
        <main className="p-4 sm:p-6 lg:p-8 flex-1 w-full max-w-[1720px] mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}

