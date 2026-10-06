import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { cn } from '../utils/cn';
import { useAuth } from '../context/AuthContext';
import { useSocket } from '../hooks/useSocket';
import { useToast } from '../hooks/useToast';
import { guardianService } from '../services';
import { formatRelativeTime, formatTimestamp } from '../utils/format';
import { normalizeRisk } from '../utils/risk';
import {
  Button,
  Badge,
  RiskBadge,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
  EmptyState,
  Alert,
  Input,
  Select,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../components/ui';
import {
  ShieldCheck,
  Users,
  UserPlus,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Search,
  Check,
  X,
  Clock,
  ShieldAlert,
  Copy,
  Info,
  HeartHandshake,
  Shield,
  Loader2,
  Mail,
  UserX,
} from 'lucide-react';

export function GuardianPage() {
  const { user } = useAuth();
  const { onIncident, isConnected } = useSocket();
  const { success: toastSuccess, error: toastError, warning: toastWarning } = useToast();

  // Primary data states
  const [links, setLinks] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isLoadingLinks, setIsLoadingLinks] = useState(true);
  const [isLoadingAlerts, setIsLoadingAlerts] = useState(true);
  const [linksError, setLinksError] = useState(null);
  const [alertsError, setAlertsError] = useState(null);

  // Active view tab: 'links' | 'alerts'
  const [activeTab, setActiveTab] = useState('links');
  // Filter for links tab: 'all' | 'active' | 'pending' | 'revoked'
  const [statusFilter, setStatusFilter] = useState('all');

  // Link Invite Modal State
  const [inviteModalOpen, setInviteModalOpen] = useState(false);
  const [searchEmail, setSearchEmail] = useState('');
  const [isSearchingUser, setIsSearchingUser] = useState(false);
  const [foundUser, setFoundUser] = useState(null);
  const [searchError, setSearchError] = useState(null);
  const [linkRoleMode, setLinkRoleMode] = useState('protect_dependent'); // 'protect_dependent' | 'protected_by'
  const [isSubmittingLink, setIsSubmittingLink] = useState(false);

  // Revoke Confirmation Dialog State
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [targetRevokeLink, setTargetRevokeLink] = useState(null);
  const [isRevoking, setIsRevoking] = useState(false);

  // Action loading states per link ID: { [linkId]: 'accepting' | 'declining' | 'revoking' }
  const [actionLoadingMap, setActionLoadingMap] = useState({});

  // 1. Fetch Guardian Links
  const fetchLinks = useCallback(async () => {
    setIsLoadingLinks(true);
    setLinksError(null);
    try {
      const data = await guardianService.listLinks({ status: 'all' });
      setLinks(data || []);
    } catch (err) {
      console.error('[GuardianPage fetchLinks error]', err);
      setLinksError(err.message || 'Failed to retrieve guardian links.');
    } finally {
      setIsLoadingLinks(false);
    }
  }, []);

  // 2. Fetch Dependent Alerts
  const fetchAlerts = useCallback(async () => {
    setIsLoadingAlerts(true);
    setAlertsError(null);
    try {
      const data = await guardianService.getAlerts();
      setAlerts(data || []);
    } catch (err) {
      console.error('[GuardianPage fetchAlerts error]', err);
      setAlertsError(err.message || 'Failed to retrieve dependent alerts.');
    } finally {
      setIsLoadingAlerts(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    if (user?.id) {
      fetchLinks();
      fetchAlerts();
    }
  }, [user?.id, fetchLinks, fetchAlerts]);

  // Real-time WebSocket incident notifications for Guardian Mode
  useEffect(() => {
    if (!onIncident) return;
    const unsubscribe = onIncident((incident) => {
      if (!incident) return;
      // Re-fetch alerts and links live when an incident occurs
      fetchAlerts();
      fetchLinks();
      toastWarning({
        title: 'Guardian Threat Detected',
        description: `High-risk incident reported: ${incident.threat_type?.replace(/_/g, ' ') || 'Security Threat'}`,
      });
    });
    return unsubscribe;
  }, [onIncident, fetchAlerts, fetchLinks, toastWarning]);

  // Derived metrics from real data
  const metrics = useMemo(() => {
    const currentUserId = user?.id;
    let activeDependentsCount = 0;
    let guardingYouCount = 0;
    let pendingIncomingCount = 0;
    let pendingOutgoingCount = 0;

    links.forEach((l) => {
      if (l.status === 'active') {
        if (l.guardian_user_id === currentUserId) activeDependentsCount++;
        if (l.dependent_user_id === currentUserId) guardingYouCount++;
      } else if (l.status === 'pending') {
        if (l.dependent_user_id === currentUserId) pendingIncomingCount++;
        if (l.guardian_user_id === currentUserId) pendingOutgoingCount++;
      }
    });

    return {
      activeDependentsCount,
      guardingYouCount,
      pendingIncomingCount,
      pendingOutgoingCount,
      totalPending: pendingIncomingCount + pendingOutgoingCount,
      activeAlertsCount: alerts.length,
    };
  }, [links, alerts, user?.id]);

  // Pending incoming requests directed to current user
  const incomingPendingInvites = useMemo(() => {
    return links.filter(
      (l) => l.status === 'pending' && l.dependent_user_id === user?.id
    );
  }, [links, user?.id]);

  // Filtered links list based on status filter tab
  const filteredLinks = useMemo(() => {
    if (statusFilter === 'all') return links;
    return links.filter((l) => l.status === statusFilter);
  }, [links, statusFilter]);

  // Search User by Email in Invite Modal
  const handleSearchUser = async (e) => {
    e?.preventDefault();
    if (!searchEmail.trim()) {
      setSearchError('Please enter an email address to search.');
      return;
    }
    if (searchEmail.trim().toLowerCase() === user?.email?.toLowerCase()) {
      setSearchError('You cannot establish a guardian link with your own account.');
      return;
    }

    setIsSearchingUser(true);
    setSearchError(null);
    setFoundUser(null);

    try {
      const res = await guardianService.searchUserByEmail(searchEmail.trim());
      const targetUser = res?.user || (Array.isArray(res?.users) ? res.users[0] : null) || (res?.id ? res : null);
      if (!targetUser || !targetUser.id) {
        setSearchError('No registered CyberGuard user found with this email.');
      } else if (targetUser.id === user?.id) {
        setSearchError('You cannot link your own account as a dependent.');
      } else {
        setFoundUser(targetUser);
      }
    } catch (err) {
      if (err.status === 404 || err.code === 'NOT_FOUND') {
        setSearchError('No registered user found with this email address. The user must register first.');
      } else {
        setSearchError(err.message || 'Failed to search for user.');
      }
    } finally {
      setIsSearchingUser(false);
    }
  };

  // Submit Link Creation
  const handleCreateLinkSubmit = async () => {
    if (!foundUser || !foundUser.id) {
      setSearchError('Please search and select a valid registered user first.');
      return;
    }

    setIsSubmittingLink(true);
    setSearchError(null);

    const guardian_user_id = linkRoleMode === 'protect_dependent' ? user.id : foundUser.id;
    const dependent_user_id = linkRoleMode === 'protect_dependent' ? foundUser.id : user.id;

    try {
      await guardianService.createLink({
        guardian_user_id,
        dependent_user_id,
      });

      toastSuccess({
        title: 'Guardian Link Sent',
        description: `Invitation sent to ${foundUser.email}. Awaiting acceptance.`,
      });

      // Reset and close
      setInviteModalOpen(false);
      setSearchEmail('');
      setFoundUser(null);
      setSearchError(null);
      fetchLinks();
    } catch (err) {
      setSearchError(err.message || 'Failed to create guardian link. Please verify inputs.');
    } finally {
      setIsSubmittingLink(false);
    }
  };

  // Accept Link
  const handleAcceptLink = async (linkId) => {
    setActionLoadingMap((prev) => ({ ...prev, [linkId]: 'accepting' }));
    try {
      await guardianService.acceptLink(linkId);
      toastSuccess({
        title: 'Link Accepted',
        description: 'You have accepted the Guardian protection link.',
      });
      fetchLinks();
      fetchAlerts();
    } catch (err) {
      toastError({
        title: 'Failed to Accept',
        description: err.message || 'Could not accept guardian link.',
      });
    } finally {
      setActionLoadingMap((prev) => {
        const copy = { ...prev };
        delete copy[linkId];
        return copy;
      });
    }
  };

  // Decline Link
  const handleDeclineLink = async (linkId) => {
    setActionLoadingMap((prev) => ({ ...prev, [linkId]: 'declining' }));
    try {
      await guardianService.declineLink(linkId);
      toastSuccess({
        title: 'Link Declined',
        description: 'You have declined the Guardian protection invitation.',
      });
      fetchLinks();
    } catch (err) {
      toastError({
        title: 'Failed to Decline',
        description: err.message || 'Could not decline guardian link.',
      });
    } finally {
      setActionLoadingMap((prev) => {
        const copy = { ...prev };
        delete copy[linkId];
        return copy;
      });
    }
  };

  // Execute Revoke Link
  const handleExecuteRevoke = async () => {
    if (!targetRevokeLink?.id && !targetRevokeLink?.link_id) return;
    const linkId = targetRevokeLink.id || targetRevokeLink.link_id;

    setIsRevoking(true);
    try {
      await guardianService.revokeLink(linkId);
      toastSuccess({
        title: 'Protection Revoked',
        description: 'The Guardian link has been revoked.',
      });
      setRevokeModalOpen(false);
      setTargetRevokeLink(null);
      fetchLinks();
      fetchAlerts();
    } catch (err) {
      toastError({
        title: 'Failed to Revoke',
        description: err.message || 'Could not revoke guardian link.',
      });
    } finally {
      setIsRevoking(false);
    }
  };

  // Copy Account ID
  const handleCopyAccountId = () => {
    if (user?.id) {
      navigator.clipboard?.writeText(user.id);
      toastSuccess({
        title: 'Account ID Copied',
        description: 'User ID copied to clipboard.',
      });
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto w-full pb-16 font-sans">
      {/* 1. Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
              Guardian Mode
            </h1>
            <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30 bg-primary/5">
              Live Protection
            </Badge>
          </div>
          <p className="font-body text-xs text-muted-foreground leading-relaxed max-w-2xl">
            Protect vulnerable family members, children, and non-technical dependents against fraud, deepfakes, and phishing scams.
            When linked, high and critical threat alerts detected on dependent devices are automatically forwarded to you in real time.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 shrink-0">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              fetchLinks();
              fetchAlerts();
            }}
            disabled={isLoadingLinks || isLoadingAlerts}
            className="font-mono text-xs"
          >
            <RotateCcw className={cn('w-3.5 h-3.5 mr-1.5', (isLoadingLinks || isLoadingAlerts) && 'animate-spin')} />
            Refresh
          </Button>

          <Button
            type="button"
            variant="default"
            size="sm"
            onClick={() => {
              setInviteModalOpen(true);
              setSearchEmail('');
              setFoundUser(null);
              setSearchError(null);
            }}
            className="font-mono text-xs font-semibold"
          >
            <UserPlus className="w-3.5 h-3.5 mr-1.5" />
            Link Dependent
          </Button>
        </div>
      </div>

      {/* 2. User Context Banner */}
      <div className="p-3.5 rounded-xl bg-card border border-border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-primary/15 text-primary font-bold flex items-center justify-center font-mono">
            {user?.email ? user.email.slice(0, 2).toUpperCase() : 'GU'}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-foreground">
                {user?.full_name?.trim() || user?.email?.split('@')[0] || 'Authenticated User'}
              </span>
              <Badge variant="secondary" className="text-[10px] font-mono capitalize">
                {user?.role?.replace(/_/g, ' ') || 'User'}
              </Badge>
            </div>
            <span className="text-muted-foreground font-mono text-[11px]">{user?.email}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground bg-muted/50 px-3 py-1.5 rounded-lg border border-border/80">
          <span className="font-semibold text-foreground/80">Your Account ID:</span>
          <span className="truncate max-w-[150px] sm:max-w-[200px]" title={user?.id}>
            {user?.id || '—'}
          </span>
          <button
            type="button"
            onClick={handleCopyAccountId}
            className="text-primary hover:text-primary/80 transition-colors p-1"
            title="Copy Account ID"
            aria-label="Copy Account ID"
          >
            <Copy className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 3. Metric KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-mono uppercase">
            <span>Protected Dependents</span>
            <Users className="w-4 h-4 text-primary" />
          </div>
          <div className="font-mono text-2xl font-bold text-foreground">
            {isLoadingLinks ? '—' : metrics.activeDependentsCount}
          </div>
          <p className="text-[11px] text-muted-foreground">Active family accounts under your watch</p>
        </div>

        {/* Metric 2 */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-mono uppercase">
            <span>Guarding You</span>
            <Shield className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="font-mono text-2xl font-bold text-foreground">
            {isLoadingLinks ? '—' : metrics.guardingYouCount}
          </div>
          <p className="text-[11px] text-muted-foreground">Trusted guardians protecting this account</p>
        </div>

        {/* Metric 3 */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-mono uppercase">
            <span>Pending Invites</span>
            <Clock className="w-4 h-4 text-amber-500" />
          </div>
          <div className="font-mono text-2xl font-bold text-foreground">
            {isLoadingLinks ? '—' : metrics.totalPending}
          </div>
          <p className="text-[11px] text-muted-foreground">
            {metrics.pendingIncomingCount > 0
              ? `${metrics.pendingIncomingCount} incoming waiting for you`
              : 'Invitations awaiting acceptance'}
          </p>
        </div>

        {/* Metric 4 */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-mono uppercase">
            <span>Dependent Alerts</span>
            <ShieldAlert className="w-4 h-4 text-destructive" />
          </div>
          <div className="font-mono text-2xl font-bold text-foreground">
            {isLoadingAlerts ? '—' : metrics.activeAlertsCount}
          </div>
          <p className="text-[11px] text-muted-foreground">High & critical threat incidents reported</p>
        </div>
      </div>

      {/* 4. Incoming Pending Invitations Callout (if any) */}
      {incomingPendingInvites.length > 0 && (
        <div className="space-y-3">
          {incomingPendingInvites.map((invite) => {
            const linkId = invite.id || invite.link_id;
            const currentAction = actionLoadingMap[linkId];
            return (
              <div
                key={linkId}
                className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-start gap-3">
                  <HeartHandshake className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-foreground text-xs sm:text-sm">
                        Protection Request from {invite.guardian_email || 'Guardian'}
                      </span>
                      <Badge variant="warning" className="text-[10px]">
                        Action Required
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {invite.guardian_email} wants to link as your Guardian. If accepted, high and critical scam, phishing,
                      and deepfake alerts detected on your account will be shared with them to keep you safe.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => handleDeclineLink(linkId)}
                    disabled={Boolean(currentAction)}
                    className="h-8 text-xs text-destructive hover:bg-destructive/10"
                  >
                    {currentAction === 'declining' ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" />
                    ) : (
                      <X className="w-3.5 h-3.5 mr-1" />
                    )}
                    Decline
                  </Button>

                  <Button
                    type="button"
                    variant="default"
                    size="sm"
                    onClick={() => handleAcceptLink(linkId)}
                    disabled={Boolean(currentAction)}
                    className="h-8 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    {currentAction === 'accepting' ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" />
                    ) : (
                      <Check className="w-3.5 h-3.5 mr-1" />
                    )}
                    Accept Protection
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 5. Main Navigation Tabs */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveTab('links')}
              className={cn(
                'py-2 px-3.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2',
                activeTab === 'links'
                  ? 'bg-muted text-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <Users className="w-4 h-4 text-primary" />
              <span>Protected Dependents & Links</span>
              <Badge variant="outline" className="font-mono text-[10px] ml-1">
                {links.length}
              </Badge>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('alerts')}
              className={cn(
                'py-2 px-3.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2',
                activeTab === 'alerts'
                  ? 'bg-muted text-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span>Dependent Threat Telemetry</span>
              {alerts.length > 0 && (
                <Badge variant="danger" className="font-mono text-[10px] ml-1">
                  {alerts.length}
                </Badge>
              )}
            </button>
          </div>
        </div>

        {/* TAB 1: GUARDIAN LINKS */}
        {activeTab === 'links' && (
          <div className="space-y-4">
            {/* Filter pills */}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-1.5 text-xs">
                {['all', 'active', 'pending', 'revoked'].map((filterKey) => (
                  <button
                    key={filterKey}
                    type="button"
                    onClick={() => setStatusFilter(filterKey)}
                    className={cn(
                      'px-2.5 py-1 rounded-md text-xs font-medium capitalize transition-colors',
                      statusFilter === filterKey
                        ? 'bg-primary text-primary-foreground font-semibold shadow-sm'
                        : 'bg-muted/60 text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {filterKey}
                  </button>
                ))}
              </div>

              <span className="text-[11px] font-mono text-muted-foreground">
                Showing {filteredLinks.length} of {links.length} links
              </span>
            </div>

            {/* Error Notice */}
            {linksError && (
              <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-destructive text-xs space-y-1">
                <span className="font-semibold block">Failed to load guardian links</span>
                <p className="leading-relaxed text-destructive/90">{linksError}</p>
              </div>
            )}

            {/* Loading Skeleton */}
            {isLoadingLinks && (
              <div className="p-6 rounded-xl bg-card border border-border space-y-3 animate-pulse">
                <div className="w-40 h-5 bg-muted rounded"></div>
                <div className="w-full h-12 bg-muted/60 rounded"></div>
                <div className="w-full h-12 bg-muted/60 rounded"></div>
              </div>
            )}

            {/* Empty State */}
            {!isLoadingLinks && filteredLinks.length === 0 && (
              <EmptyState
                icon={Users}
                title={
                  statusFilter === 'all'
                    ? 'No Guardian Links Established'
                    : `No ${statusFilter} Guardian Links`
                }
                description={
                  statusFilter === 'all'
                    ? 'Link a family member or dependent to start receiving real-time threat notifications.'
                    : `There are currently no guardian links with '${statusFilter}' status.`
                }
                actionLabel={statusFilter === 'all' ? 'Link Dependent Now' : undefined}
                onAction={
                  statusFilter === 'all'
                    ? () => {
                        setInviteModalOpen(true);
                        setSearchEmail('');
                        setFoundUser(null);
                        setSearchError(null);
                      }
                    : undefined
                }
              />
            )}

            {/* Links List Cards / Table */}
            {!isLoadingLinks && filteredLinks.length > 0 && (
              <div className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-muted/50 border-b border-border text-muted-foreground font-mono uppercase text-[10px]">
                      <tr>
                        <th className="py-3 px-4">Partner Account</th>
                        <th className="py-3 px-4">Relationship</th>
                        <th className="py-3 px-4">Link Status</th>
                        <th className="py-3 px-4">Created</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {filteredLinks.map((link) => {
                        const linkId = link.id || link.link_id;
                        const isUserGuardian = link.guardian_user_id === user?.id;
                        const partnerEmail = isUserGuardian ? link.dependent_email : link.guardian_email;
                        const partnerRoleLabel = isUserGuardian ? 'Dependent' : 'Guardian';
                        const currentAction = actionLoadingMap[linkId];

                        return (
                          <tr key={linkId} className="hover:bg-muted/30 transition-colors">
                            {/* Partner Email */}
                            <td className="py-3.5 px-4">
                              <div className="flex items-center gap-2.5">
                                <div className="w-7 h-7 rounded-full bg-muted flex items-center justify-center font-bold text-[11px] text-foreground">
                                  {partnerEmail ? partnerEmail.slice(0, 2).toUpperCase() : 'PA'}
                                </div>
                                <div className="space-y-0.5">
                                  <span className="font-semibold text-foreground block">
                                    {partnerEmail || 'Account User'}
                                  </span>
                                  <span className="text-[10px] font-mono text-muted-foreground truncate max-w-[180px] block">
                                    ID: {isUserGuardian ? link.dependent_user_id : link.guardian_user_id}
                                  </span>
                                </div>
                              </div>
                            </td>

                            {/* Relationship Type */}
                            <td className="py-3.5 px-4">
                              {isUserGuardian ? (
                                <Badge variant="accent" className="text-[10px] font-mono">
                                  Protecting ({partnerRoleLabel})
                                </Badge>
                              ) : (
                                <Badge variant="secondary" className="text-[10px] font-mono">
                                  Protected by ({partnerRoleLabel})
                                </Badge>
                              )}
                            </td>

                            {/* Status */}
                            <td className="py-3.5 px-4">
                              {link.status === 'active' && (
                                <Badge variant="success" className="text-[10px] capitalize">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5" />
                                  Active
                                </Badge>
                              )}
                              {link.status === 'pending' && (
                                <Badge variant="warning" className="text-[10px] capitalize">
                                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500 mr-1.5 animate-pulse" />
                                  Pending
                                </Badge>
                              )}
                              {link.status === 'revoked' && (
                                <Badge variant="muted" className="text-[10px] capitalize">
                                  Revoked
                                </Badge>
                              )}
                            </td>

                            {/* Timestamp */}
                            <td className="py-3.5 px-4 font-mono text-[11px] text-muted-foreground">
                              {link.created_at ? formatRelativeTime(link.created_at) : '—'}
                            </td>

                            {/* Action Buttons */}
                            <td className="py-3.5 px-4 text-right">
                              {link.status === 'pending' && (
                                <div className="flex items-center justify-end gap-1.5">
                                  {/* If user is the dependent, they can accept or decline */}
                                  {!isUserGuardian ? (
                                    <>
                                      <Button
                                        type="button"
                                        variant="outline"
                                        size="sm"
                                        onClick={() => handleDeclineLink(linkId)}
                                        disabled={Boolean(currentAction)}
                                        className="h-7 px-2 text-xs text-destructive hover:bg-destructive/10"
                                      >
                                        {currentAction === 'declining' ? (
                                          <Loader2 className="w-3 h-3 animate-spin" />
                                        ) : (
                                          'Decline'
                                        )}
                                      </Button>
                                      <Button
                                        type="button"
                                        variant="default"
                                        size="sm"
                                        onClick={() => handleAcceptLink(linkId)}
                                        disabled={Boolean(currentAction)}
                                        className="h-7 px-2.5 text-xs bg-emerald-600 hover:bg-emerald-700"
                                      >
                                        {currentAction === 'accepting' ? (
                                          <Loader2 className="w-3 h-3 animate-spin" />
                                        ) : (
                                          'Accept'
                                        )}
                                      </Button>
                                    </>
                                  ) : (
                                    /* If user sent the invite, they can cancel / revoke it */
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => {
                                        setTargetRevokeLink(link);
                                        setRevokeModalOpen(true);
                                      }}
                                      className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
                                    >
                                      Cancel Invite
                                    </Button>
                                  )}
                                </div>
                              )}

                              {link.status === 'active' && (
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setTargetRevokeLink(link);
                                    setRevokeModalOpen(true);
                                  }}
                                  className="h-7 px-2.5 text-xs text-muted-foreground hover:text-destructive"
                                >
                                  <UserX className="w-3.5 h-3.5 mr-1" />
                                  Revoke
                                </Button>
                              )}

                              {link.status === 'revoked' && (
                                <span className="text-[11px] font-mono text-muted-foreground/60 italic">
                                  Closed
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: DEPENDENT ALERTS */}
        {activeTab === 'alerts' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Real-time critical threat stream for your active dependents.</span>
              <span className="font-mono text-[11px]">
                {alerts.length} {alerts.length === 1 ? 'alert' : 'alerts'} recorded
              </span>
            </div>

            {/* Error Notice */}
            {alertsError && (
              <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-destructive text-xs space-y-1">
                <span className="font-semibold block">Failed to load dependent alerts</span>
                <p className="leading-relaxed text-destructive/90">{alertsError}</p>
              </div>
            )}

            {/* Loading Skeleton */}
            {isLoadingAlerts && (
              <div className="p-6 rounded-xl bg-card border border-border space-y-3 animate-pulse">
                <div className="w-32 h-5 bg-muted rounded"></div>
                <div className="w-full h-16 bg-muted/60 rounded"></div>
                <div className="w-full h-16 bg-muted/60 rounded"></div>
              </div>
            )}

            {/* Empty State */}
            {!isLoadingAlerts && alerts.length === 0 && (
              <EmptyState
                icon={ShieldCheck}
                title="All Dependents Protected"
                description="There are currently zero high or critical threat incidents reported for your active dependents."
              />
            )}

            {/* Alerts List */}
            {!isLoadingAlerts && alerts.length > 0 && (
              <div className="space-y-3">
                {alerts.map((alert) => {
                  const alertId = alert.alert_id || alert.id;
                  const normRisk = normalizeRisk(alert.risk_level);

                  return (
                    <div
                      key={alertId}
                      className={cn(
                        'p-4 rounded-xl border bg-card transition-all space-y-3',
                        normRisk === 'critical'
                          ? 'border-destructive/40 shadow-sm shadow-destructive/5'
                          : 'border-amber-500/40 shadow-sm shadow-amber-500/5'
                      )}
                    >
                      {/* Alert Header */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border/80">
                        <div className="flex items-center gap-2.5">
                          <RiskBadge level={normRisk} size="md" />
                          <Badge variant="outline" className="font-mono text-xs uppercase">
                            {alert.threat_type?.replace(/_/g, ' ') || 'Threat Anomaly'}
                          </Badge>
                          <span className="text-xs font-semibold text-foreground">
                            Target: {alert.dependent_name || alert.dependent_email || 'Dependent'}
                          </span>
                        </div>

                        <span className="font-mono text-[11px] text-muted-foreground">
                          {alert.timestamp ? formatRelativeTime(alert.timestamp) : 'Recent'}
                        </span>
                      </div>

                      {/* Explanation */}
                      <div className="space-y-1">
                        <span className="font-mono text-[10px] uppercase font-semibold text-muted-foreground block">
                          Detection Explanation
                        </span>
                        <p className="text-xs text-foreground leading-relaxed">
                          {alert.explanation || 'Anomaly reported on protected dependent device.'}
                        </p>
                      </div>

                      {/* Recommended Action */}
                      {alert.recommended_action && (
                        <div className="p-2.5 rounded-lg bg-muted/40 border border-border flex items-start gap-2 text-xs">
                          <CheckCircle2 className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                          <span className="text-foreground leading-snug">
                            {alert.recommended_action}
                          </span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* 6. LINK / INVITE DEPENDENT DIALOG */}
      <Dialog open={inviteModalOpen} onOpenChange={setInviteModalOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-primary" />
              <span>Link a Dependent or Guardian</span>
            </DialogTitle>
            <DialogDescription>
              Establish a mutual protection link. Search for a registered CyberGuard user by their email address.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Search form */}
            <form onSubmit={handleSearchUser} className="space-y-2">
              <label htmlFor="search-email-input" className="text-xs font-semibold text-foreground">
                Partner Registered Email
              </label>
              <div className="flex gap-2">
                <Input
                  id="search-email-input"
                  type="email"
                  placeholder="family.member@example.com"
                  value={searchEmail}
                  onChange={(e) => {
                    setSearchEmail(e.target.value);
                    setSearchError(null);
                  }}
                  required
                  className="flex-1 text-xs"
                />
                <Button
                  type="submit"
                  variant="outline"
                  size="sm"
                  disabled={isSearchingUser || !searchEmail.trim()}
                  className="shrink-0 text-xs font-mono"
                >
                  {isSearchingUser ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Search className="w-3.5 h-3.5 mr-1" />
                  )}
                  Search
                </Button>
              </div>
            </form>

            {/* Search Error */}
            {searchError && (
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-destructive text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <p className="leading-relaxed">{searchError}</p>
              </div>
            )}

            {/* Found User Card */}
            {foundUser && (
              <div className="p-3.5 rounded-xl border border-primary/40 bg-primary/5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    <span className="font-semibold text-xs text-foreground">User Verified</span>
                  </div>
                  <Badge variant="outline" className="font-mono text-[10px] capitalize">
                    {foundUser.role || 'User'}
                  </Badge>
                </div>

                <div className="space-y-1 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Email:</span>
                    <span className="font-semibold text-foreground">{foundUser.email}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">ID:</span>
                    <span className="text-muted-foreground truncate max-w-[180px]">{foundUser.id}</span>
                  </div>
                </div>

                {/* Role configuration choice */}
                <div className="pt-2 border-t border-border/60 space-y-2">
                  <span className="text-xs font-semibold text-foreground block">
                    Choose Link Relationship
                  </span>
                  <div className="space-y-2 text-xs">
                    <label className="flex items-start gap-2 p-2 rounded-lg border border-border bg-card cursor-pointer hover:bg-muted/50 transition-colors">
                      <input
                        type="radio"
                        name="linkRole"
                        value="protect_dependent"
                        checked={linkRoleMode === 'protect_dependent'}
                        onChange={(e) => setLinkRoleMode(e.target.value)}
                        className="mt-0.5"
                      />
                      <div className="space-y-0.5">
                        <span className="font-semibold text-foreground block">I will protect this user</span>
                        <span className="text-muted-foreground text-[11px] block">
                          You become Guardian and receive alerts when high-risk threats target them.
                        </span>
                      </div>
                    </label>

                    <label className="flex items-start gap-2 p-2 rounded-lg border border-border bg-card cursor-pointer hover:bg-muted/50 transition-colors">
                      <input
                        type="radio"
                        name="linkRole"
                        value="protected_by"
                        checked={linkRoleMode === 'protected_by'}
                        onChange={(e) => setLinkRoleMode(e.target.value)}
                        className="mt-0.5"
                      />
                      <div className="space-y-0.5">
                        <span className="font-semibold text-foreground block">This user will protect me</span>
                        <span className="text-muted-foreground text-[11px] block">
                          They become Guardian and will be notified if your account encounters a scam.
                        </span>
                      </div>
                    </label>
                  </div>
                </div>
              </div>
            )}
          </div>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setInviteModalOpen(false)}
              disabled={isSubmittingLink}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={handleCreateLinkSubmit}
              disabled={isSubmittingLink || !foundUser}
              className="text-xs font-semibold"
            >
              {isSubmittingLink ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                  Sending Invite...
                </>
              ) : (
                'Send Invitation'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 7. REVOKE CONFIRMATION DIALOG */}
      <Dialog open={revokeModalOpen} onOpenChange={setRevokeModalOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <UserX className="w-5 h-5 text-destructive" />
              <span>Revoke Guardian Link?</span>
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke this guardian protection link with{' '}
              <strong className="text-foreground font-semibold">
                {targetRevokeLink?.dependent_email || targetRevokeLink?.guardian_email || 'partner account'}
              </strong>
              ? Real-time incident notification forwarding between these two accounts will be permanently disabled.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setRevokeModalOpen(false)}
              disabled={isRevoking}
              className="text-xs"
            >
              Keep Link
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={handleExecuteRevoke}
              disabled={isRevoking}
              className="text-xs font-semibold"
            >
              {isRevoking ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                  Revoking...
                </>
              ) : (
                'Confirm Revoke'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default GuardianPage;
