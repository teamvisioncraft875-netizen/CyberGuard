import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../hooks/useTheme';
import { authService } from '../services/authService';
import { formatTimestamp } from '../utils/format';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { ThemeToggle } from '../components/ui/ThemeToggle';
import {
  User,
  Shield,
  Moon,
  Sun,
  LogOut,
  Info,
  AlertTriangle,
  Building,
  Calendar,
  Mail,
  Sparkles,
  Copy,
  Check,
  KeyRound,
} from 'lucide-react';

export function SettingsPage() {
  const navigate = useNavigate();
  const { user: authUser, logout } = useAuth();
  const { theme, setTheme } = useTheme();

  const [profile, setProfile] = useState(authUser);
  const [copiedOrgId, setCopiedOrgId] = useState(false);
  const [isLogoutModalOpen, setIsLogoutModalOpen] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  // Fetch fresh profile data on mount to ensure all metadata is up to date
  useEffect(() => {
    let isMounted = true;
    async function loadFreshProfile() {
      try {
        const freshUser = await authService.getMe();
        if (isMounted && freshUser) {
          setProfile(freshUser);
        }
      } catch (err) {
        // Quiet fallback to existing auth context
      }
    }
    loadFreshProfile();
    return () => {
      isMounted = false;
    };
  }, []);

  const currentUser = profile || authUser;

  const handleCopyOrgId = () => {
    if (currentUser?.organization_id) {
      navigator.clipboard?.writeText(currentUser.organization_id);
      setCopiedOrgId(true);
      setTimeout(() => setCopiedOrgId(false), 2000);
    }
  };

  const handleConfirmLogout = async () => {
    setIsLoggingOut(true);
    try {
      await logout();
      setIsLogoutModalOpen(false);
      navigate('/login', { replace: true });
    } catch (err) {
      console.error('[SettingsPage] Global logout error:', err);
    } finally {
      setIsLoggingOut(false);
    }
  };

  const getRoleBadgeVariant = (role) => {
    switch (role?.toLowerCase()) {
      case 'admin':
        return 'default';
      case 'employee':
        return 'accent';
      case 'individual':
      default:
        return 'outline';
    }
  };

  return (
    <div className="space-y-6 max-w-[1200px] mx-auto w-full pb-12 font-sans">
      {/* 1. Page Header */}
      <div className="pb-4 border-b border-border">
        <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
          Settings
        </h1>
        <p className="font-body text-xs text-muted-foreground mt-1">
          Manage your account parameters, interface preferences, and active security sessions.
        </p>
      </div>

      <div className="space-y-6">
        {/* 2. Account Section (Read-Only) */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <User className="w-5 h-5 text-primary" />
                Account
              </CardTitle>
              <Badge variant="outline" size="sm" className="font-mono text-[10px]">
                Read-Only
              </Badge>
            </div>
            <CardDescription>
              Your verified account credentials and tenant affiliation.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Email Address */}
              <div className="p-3.5 rounded-lg border border-border bg-muted/20 space-y-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground font-medium">
                  <Mail className="w-3.5 h-3.5" />
                  Email Address
                </div>
                <div className="text-sm font-medium text-foreground font-mono truncate">
                  {currentUser?.email || '—'}
                </div>
              </div>

              {/* Account Role */}
              <div className="p-3.5 rounded-lg border border-border bg-muted/20 space-y-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground font-medium">
                  <Shield className="w-3.5 h-3.5" />
                  Account Role
                </div>
                <div className="flex items-center gap-2 pt-0.5">
                  <Badge variant={getRoleBadgeVariant(currentUser?.role)} size="md" className="capitalize">
                    {currentUser?.role || 'individual'}
                  </Badge>
                </div>
              </div>

              {/* Account Created Date */}
              <div className="p-3.5 rounded-lg border border-border bg-muted/20 space-y-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground font-medium">
                  <Calendar className="w-3.5 h-3.5" />
                  Account Created
                </div>
                <div className="text-sm font-medium text-foreground font-mono">
                  {currentUser?.created_at ? formatTimestamp(currentUser.created_at) : '—'}
                </div>
              </div>

              {/* Organization ID */}
              <div className="p-3.5 rounded-lg border border-border bg-muted/20 space-y-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground font-medium">
                  <Building className="w-3.5 h-3.5" />
                  Organization ID
                </div>
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-medium font-mono truncate text-foreground">
                    {currentUser?.organization_id ? (
                      <span title={currentUser.organization_id}>{currentUser.organization_id}</span>
                    ) : (
                      <span className="text-muted-foreground font-sans text-xs">No organization</span>
                    )}
                  </div>
                  {currentUser?.organization_id && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-xs shrink-0 text-muted-foreground hover:text-foreground"
                      onClick={handleCopyOrgId}
                      title="Copy Organization ID"
                    >
                      {copiedOrgId ? (
                        <Check className="w-3 h-3 text-emerald-500" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </Button>
                  )}
                </div>
              </div>
            </div>

            {/* Profile editing note */}
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-muted/40 border border-border text-xs text-muted-foreground">
              <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
              <span>
                Profile editing is not yet available. Account credentials, user roles, and organization affiliations are immutable once provisioned.
              </span>
            </div>
          </CardContent>
        </Card>

        {/* 3. Appearance Section */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <Moon className="w-5 h-5 text-primary" />
                Appearance
              </CardTitle>
              <ThemeToggle variant="outline" size="sm" />
            </div>
            <CardDescription>
              Customize dashboard visual theme and high-contrast color mode.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg border border-border bg-muted/20">
              <div className="space-y-1">
                <div className="text-sm font-medium text-foreground">Theme Preference</div>
                <div className="text-xs text-muted-foreground">
                  Choose between high-contrast Dark Mode (recommended for SOC displays) or Light Mode.
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant={theme === 'dark' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTheme('dark')}
                  icon={<Moon className="w-3.5 h-3.5" />}
                  className="text-xs"
                >
                  Dark
                </Button>
                <Button
                  variant={theme === 'light' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setTheme('light')}
                  icon={<Sun className="w-3.5 h-3.5" />}
                  className="text-xs"
                >
                  Light
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* 4. Security Section */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-primary" />
              Security & Sessions
            </CardTitle>
            <CardDescription>
              Manage active authorization sessions and cryptographic token invalidation.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg border border-border bg-muted/20">
              <div className="space-y-1">
                <div className="text-sm font-medium text-foreground">Global Session Revocation</div>
                <div className="text-xs text-muted-foreground max-w-xl">
                  Revoke all active refresh tokens in PostgreSQL and Redis. This immediately terminates your session across all devices and browsers.
                </div>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setIsLogoutModalOpen(true)}
                icon={<LogOut className="w-3.5 h-3.5" />}
                className="shrink-0"
              >
                Log Out of All Sessions
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* 5. Roadmap Note */}
        <div className="p-4 rounded-xl border border-dashed border-border bg-card/40 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Sparkles className="w-4 h-4 text-primary shrink-0" />
            <div className="text-xs">
              <span className="font-semibold text-foreground">More settings coming soon</span>
              <span className="text-muted-foreground ml-1.5">
                — Password changes, notification preference rules, and team member management will be enabled in future updates.
              </span>
            </div>
          </div>
          <Badge variant="outline" size="sm" className="text-[10px] uppercase font-mono tracking-wider">
            Roadmap
          </Badge>
        </div>
      </div>

      {/* Confirmation Modal for Logging Out Everywhere */}
      <Modal
        isOpen={isLogoutModalOpen}
        onClose={() => !isLoggingOut && setIsLogoutModalOpen(false)}
        title="Log Out of All Sessions"
        description="Confirm global session termination"
        size="md"
      >
        <div className="space-y-4 pt-2">
          <div className="flex items-start gap-3 p-3.5 rounded-lg bg-destructive/10 border border-destructive/20 text-xs">
            <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold text-destructive dark:text-red-400">
                This will invalidate your session on all devices
              </p>
              <p className="text-muted-foreground leading-relaxed">
                Per CyberGuard security policy, terminating your session revokes all active refresh tokens associated with your account across all workstations, mobile devices, and browser tabs. You will be redirected to the sign-in screen.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsLogoutModalOpen(false)}
              disabled={isLoggingOut}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleConfirmLogout}
              isLoading={isLoggingOut}
              icon={<LogOut className="w-4 h-4" />}
            >
              Confirm & Log Out Everywhere
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
