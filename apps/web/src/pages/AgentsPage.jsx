import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { cn } from '../utils/cn';
import { formatRelativeTime, formatTimestamp } from '../utils/format';
import {
  Button,
  Badge,
  Input,
  EmptyState,
  Alert,
  Skeleton,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  Drawer,
} from '../components/ui';
import {
  Server,
  Laptop,
  HardDrive,
  Cpu,
  Bot,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Search,
  Filter,
  Plus,
  Shield,
  Flame,
  Terminal,
  Info,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Radio,
} from 'lucide-react';
import { agentService } from '../services/agentService';
import { toast } from 'sonner';

export function AgentsPage({ onTriggerToast }) {
  const navigate = useNavigate();
  const { user, isAdmin } = useAuth();

  // State: Agents list & pagination
  const [agents, setAgents] = useState([]);
  const [totalAgents, setTotalAgents] = useState(0);
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // State: Filters
  const [statusFilter, setStatusFilter] = useState('all'); // all, online, offline, disabled, pending
  const [searchQuery, setSearchQuery] = useState('');
  const [platformFilter, setPlatformFilter] = useState('all');

  // State: Copy feedback
  const [copiedId, setCopiedId] = useState(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);

  // State: Selected agent for Inspection Drawer
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentStatusDetail, setAgentStatusDetail] = useState(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState(null);

  // State: Enrollment Token Generation Modal
  const [isTokenModalOpen, setIsTokenModalOpen] = useState(false);
  const [validHours, setValidHours] = useState(24);
  const [isGeneratingToken, setIsGeneratingToken] = useState(false);
  const [generatedTokenData, setGeneratedTokenData] = useState(null);
  const [tokenError, setTokenError] = useState(null);

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Fetch Agents
  // ─────────────────────────────────────────────────────────────────────────────
  const fetchAgents = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = {
        limit,
        offset,
      };
      if (statusFilter !== 'all') {
        params.status = statusFilter;
      }

      const res = await agentService.listAgents(params);
      setAgents(res?.agents || []);
      setTotalAgents(res?.total || 0);
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to retrieve agent fleet';
      setError(msg);
      toast.error('Fleet Error', { description: msg });
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, statusFilter]);

  useEffect(() => {
    fetchAgents();
  }, [fetchAgents]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Fetch Detailed Agent Status for Drawer
  // ─────────────────────────────────────────────────────────────────────────────
  const handleOpenDetail = useCallback(async (agent) => {
    setSelectedAgent(agent);
    setAgentStatusDetail(null);
    setDetailError(null);
    setIsLoadingDetail(true);

    try {
      const statusRes = await agentService.getAgentStatus(agent.id);
      setAgentStatusDetail(statusRes);
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to inspect agent telemetry';
      setDetailError(msg);
    } finally {
      setIsLoadingDetail(false);
    }
  }, []);

  const handleCloseDetail = useCallback(() => {
    setSelectedAgent(null);
    setAgentStatusDetail(null);
    setDetailError(null);
  }, []);

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Generate Single-Use Enrollment Token
  // ─────────────────────────────────────────────────────────────────────────────
  const handleGenerateToken = async (e) => {
    e?.preventDefault();
    setIsGeneratingToken(true);
    setTokenError(null);
    try {
      const res = await agentService.createEnrollmentToken({
        valid_for_hours: parseInt(validHours, 10) || 24,
      });
      setGeneratedTokenData(res);
      toast.success('Enrollment Token Created', {
        description: `Valid for ${validHours} hours`,
      });
      // Refresh fleet list in background as a new 'pending' device row is created
      fetchAgents();
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to generate token';
      setTokenError(msg);
      toast.error('Token Generation Failed', { description: msg });
    } finally {
      setIsGeneratingToken(false);
    }
  };

  const handleCloseTokenModal = () => {
    setIsTokenModalOpen(false);
    setGeneratedTokenData(null);
    setTokenError(null);
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Copy Utilities
  // ─────────────────────────────────────────────────────────────────────────────
  const copyToClipboard = (text, type = 'id', id = null) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    if (type === 'id') {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } else if (type === 'token') {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } else if (type === 'command') {
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 2000);
    }
    toast.success('Copied to clipboard');
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. Client-Side Search & Platform Filtering
  // ─────────────────────────────────────────────────────────────────────────────
  const filteredAgents = useMemo(() => {
    return agents.filter((agent) => {
      // Platform filter
      if (platformFilter !== 'all') {
        const p = (agent.platform || '').toLowerCase();
        if (platformFilter === 'windows' && !p.includes('win')) return false;
        if (platformFilter === 'linux' && !p.includes('linux')) return false;
        if (platformFilter === 'darwin' && !p.includes('mac') && !p.includes('darwin')) return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const hostname = (agent.hostname || '').toLowerCase();
        const os = (agent.os || '').toLowerCase();
        const id = (agent.id || '').toLowerCase();
        const version = (agent.agent_version || '').toLowerCase();
        return hostname.includes(query) || os.includes(query) || id.includes(query) || version.includes(query);
      }

      return true;
    });
  }, [agents, platformFilter, searchQuery]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. Real Fleet KPI Metrics (Calculated Strictly From Real Backend Data)
  // ─────────────────────────────────────────────────────────────────────────────
  const metrics = useMemo(() => {
    const total = totalAgents;
    let onlineCount = 0;
    let offlineCount = 0;
    let unhealthyCount = 0;
    let pendingCount = 0;

    agents.forEach((agent) => {
      const isStale = typeof agent.last_heartbeat_age_seconds === 'number' && agent.last_heartbeat_age_seconds > 180;
      if (agent.status === 'online') {
        if (isStale) {
          unhealthyCount++;
        } else {
          onlineCount++;
        }
      } else if (agent.status === 'pending') {
        pendingCount++;
      } else if (agent.status === 'disabled') {
        unhealthyCount++;
      } else {
        offlineCount++;
      }
    });

    return {
      total,
      onlineCount,
      offlineCount,
      unhealthyCount,
      pendingCount,
    };
  }, [agents, totalAgents]);

  // Helper to render platform/OS icon
  const renderPlatformIcon = (platform, os) => {
    const p = (platform || os || '').toLowerCase();
    if (p.includes('win')) {
      return <Laptop className="w-4 h-4 text-sky-400" title="Windows" />;
    }
    if (p.includes('linux') || p.includes('ubuntu') || p.includes('debian')) {
      return <Terminal className="w-4 h-4 text-amber-400" title="Linux" />;
    }
    if (p.includes('darwin') || p.includes('mac') || p.includes('apple')) {
      return <HardDrive className="w-4 h-4 text-purple-400" title="macOS" />;
    }
    return <Server className="w-4 h-4 text-muted-foreground" title="Host Server" />;
  };

  // Helper to render status badge
  const renderStatusBadge = (status, heartbeatAge) => {
    const isStale = typeof heartbeatAge === 'number' && heartbeatAge > 180;

    if (status === 'online') {
      if (isStale) {
        return (
          <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30 gap-1.5 py-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
            Online (Lagging)
          </Badge>
        );
      }
      return (
        <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 gap-1.5 py-0.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
          Online
        </Badge>
      );
    }

    if (status === 'pending') {
      return (
        <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30 gap-1.5 py-0.5">
          <Clock className="w-3 h-3 text-blue-400" />
          Pending Enrollment
        </Badge>
      );
    }

    if (status === 'disabled') {
      return (
        <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/30 gap-1.5 py-0.5">
          <XCircle className="w-3 h-3 text-destructive" />
          Disabled
        </Badge>
      );
    }

    return (
      <Badge variant="outline" className="bg-muted text-muted-foreground border-border gap-1.5 py-0.5">
        <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/60" />
        Offline
      </Badge>
    );
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // Non-Admin Guard
  // ─────────────────────────────────────────────────────────────────────────────
  if (!isAdmin) {
    return (
      <div className="p-8 max-w-4xl mx-auto">
        <Alert variant="destructive" className="border-destructive/40 bg-destructive/10">
          <ShieldAlert className="w-5 h-5 text-destructive" />
          <div className="ml-3">
            <h3 className="text-base font-semibold text-destructive">Administrative Access Required</h3>
            <p className="text-sm text-destructive/80 mt-1">
              Enterprise Agent Fleet management is restricted to organization administrators. Your current session does
              not possess the required <code className="font-mono text-xs">admin</code> privilege.
            </p>
          </div>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────────────────────
          1. Header Banner & Action Bar
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Bot className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                Enterprise Agent Fleet
                <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 font-mono text-xs font-normal">
                  Phase 5
                </Badge>
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Monitor enrolled host daemons, verify heartbeat liveness, and provision secure enrollment credentials.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAgents}
            disabled={isLoading}
            className="gap-2 border-border/80 hover:bg-muted/60"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin text-primary')} />
            Refresh Fleet
          </Button>

          <Button
            size="sm"
            onClick={() => setIsTokenModalOpen(true)}
            className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Enroll New Agent
          </Button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          2. Fleet Overview KPI Cards
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5">
        {/* Total Fleet */}
        <div className="p-4 rounded-xl border border-border/70 bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Total Enrolled</span>
            <Server className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-foreground">
            {isLoading ? <Skeleton className="h-8 w-12" /> : metrics.total}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">Tenant fleet inventory</p>
        </div>

        {/* Online Agents */}
        <div className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-emerald-400">Online & Active</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-emerald-400">
            {isLoading ? <Skeleton className="h-8 w-12" /> : metrics.onlineCount}
          </div>
          <p className="text-[11px] text-emerald-500/80 mt-1">Heartbeat &le; 180s</p>
        </div>

        {/* Offline Agents */}
        <div className="p-4 rounded-xl border border-border/70 bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Offline</span>
            <XCircle className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-muted-foreground">
            {isLoading ? <Skeleton className="h-8 w-12" /> : metrics.offlineCount}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">Disconnected hosts</p>
        </div>

        {/* Unhealthy / Stale */}
        <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-500/5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-amber-400">Unhealthy / Stale</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-amber-400">
            {isLoading ? <Skeleton className="h-8 w-12" /> : metrics.unhealthyCount}
          </div>
          <p className="text-[11px] text-amber-500/80 mt-1">Lagging or disabled</p>
        </div>

        {/* Pending Enrollment */}
        <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5 relative overflow-hidden col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-blue-400">Pending Token</span>
            <Radio className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-blue-400">
            {isLoading ? <Skeleton className="h-8 w-12" /> : metrics.pendingCount}
          </div>
          <p className="text-[11px] text-blue-500/80 mt-1">Awaiting daemon link</p>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          3. Filters & Search Bar
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 p-3 rounded-xl border border-border/60 bg-card/40">
        <div className="flex flex-1 items-center gap-2">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search hostname, OS, version, UUID..."
              className="pl-9 bg-background/80 text-sm h-9"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="text-xs text-muted-foreground font-medium hidden sm:inline-block">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setOffset(0);
              }}
              className="h-9 text-xs rounded-md border border-input bg-background/80 px-2.5 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="all">All Statuses</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="disabled">Disabled</option>
              <option value="pending">Pending</option>
            </select>
          </div>

          {/* Platform Filter */}
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="text-xs text-muted-foreground font-medium hidden sm:inline-block">Platform:</span>
            <select
              value={platformFilter}
              onChange={(e) => setPlatformFilter(e.target.value)}
              className="h-9 text-xs rounded-md border border-input bg-background/80 px-2.5 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="all">All Platforms</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="darwin">macOS</option>
            </select>
          </div>
        </div>

        <div className="text-xs text-muted-foreground self-center shrink-0">
          Showing <span className="font-medium text-foreground">{filteredAgents.length}</span> of{' '}
          <span className="font-medium text-foreground">{totalAgents}</span> enrolled agents
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          4. Agent Fleet Table / List View
      ───────────────────────────────────────────────────────────────────────────── */}
      {error ? (
        <Alert variant="destructive" className="border-destructive/30 bg-destructive/10">
          <AlertTriangle className="w-5 h-5 text-destructive" />
          <div className="ml-3">
            <h4 className="text-sm font-semibold">Failed to Load Fleet</h4>
            <p className="text-xs text-destructive/80 mt-0.5">{error}</p>
            <Button variant="outline" size="sm" onClick={fetchAgents} className="mt-3 text-xs gap-1.5">
              <RefreshCw className="w-3 h-3" /> Retry Connection
            </Button>
          </div>
        </Alert>
      ) : isLoading ? (
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden p-6 space-y-4">
          <div className="flex items-center justify-between pb-4 border-b border-border/40">
            <Skeleton className="h-5 w-48" />
            <Skeleton className="h-5 w-24" />
          </div>
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="flex items-center justify-between py-2.5 gap-4">
              <div className="flex items-center gap-3">
                <Skeleton className="w-8 h-8 rounded-lg" />
                <div className="space-y-1.5">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-3 w-28" />
                </div>
              </div>
              <Skeleton className="h-6 w-20" />
              <Skeleton className="h-4 w-28 hidden md:block" />
              <Skeleton className="h-8 w-24" />
            </div>
          ))}
        </div>
      ) : filteredAgents.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border/80 bg-card/40 p-12 text-center">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 text-primary flex items-center justify-center mx-auto mb-4">
            <Bot className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-foreground">No Agents Found</h3>
          <p className="text-sm text-muted-foreground max-w-md mx-auto mt-1 mb-6">
            {searchQuery || statusFilter !== 'all' || platformFilter !== 'all'
              ? 'No enrolled agents match your active search filter criteria. Try resetting your filters.'
              : 'Your organization does not have any enrolled enterprise agents yet. Generate an enrollment token to connect your first host daemon.'}
          </p>
          <div className="flex items-center justify-center gap-3">
            {searchQuery || statusFilter !== 'all' || platformFilter !== 'all' ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('all');
                  setPlatformFilter('all');
                }}
              >
                Clear Filters
              </Button>
            ) : (
              <Button size="sm" onClick={() => setIsTokenModalOpen(true)} className="gap-2">
                <Plus className="w-4 h-4" /> Enroll First Agent
              </Button>
            )}
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-border/70 bg-card overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-border/60 bg-muted/30 text-muted-foreground font-mono uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4 font-semibold">Agent / Hostname</th>
                  <th className="py-3 px-4 font-semibold">Platform & OS</th>
                  <th className="py-3 px-4 font-semibold">Version</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold">Heartbeat Age</th>
                  <th className="py-3 px-4 font-semibold">Enrolled</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40">
                {filteredAgents.map((agent) => (
                  <tr key={agent.id} className="hover:bg-muted/30 transition-colors">
                    {/* Hostname & ID */}
                    <td className="py-3 px-4">
                      <div className="flex items-start gap-2.5">
                        <div className="p-1.5 rounded-md bg-muted/60 border border-border/40 shrink-0 mt-0.5">
                          {renderPlatformIcon(agent.platform, agent.os)}
                        </div>
                        <div>
                          <div className="font-semibold text-foreground text-sm flex items-center gap-1.5">
                            {agent.hostname || <span className="text-muted-foreground italic">Unregistered Host</span>}
                          </div>
                          <div className="flex items-center gap-1 text-[11px] font-mono text-muted-foreground mt-0.5">
                            <span>{agent.id.slice(0, 8)}...{agent.id.slice(-4)}</span>
                            <button
                              onClick={() => copyToClipboard(agent.id, 'id', agent.id)}
                              className="text-muted-foreground hover:text-foreground p-0.5"
                              title="Copy device UUID"
                            >
                              {copiedId === agent.id ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Platform & OS */}
                    <td className="py-3 px-4">
                      <div className="text-foreground font-medium">
                        {agent.os || (agent.platform ? agent.platform.toUpperCase() : 'Unknown OS')}
                      </div>
                      <div className="text-[11px] text-muted-foreground font-mono">
                        {agent.platform || 'native'}
                      </div>
                    </td>

                    {/* Version */}
                    <td className="py-3 px-4">
                      <Badge variant="outline" className="font-mono text-[10px] bg-muted/40 border-border/60">
                        v{agent.agent_version || '1.0.0'}
                      </Badge>
                    </td>

                    {/* Status Badge */}
                    <td className="py-3 px-4">
                      {renderStatusBadge(agent.status, agent.last_heartbeat_age_seconds)}
                    </td>

                    {/* Heartbeat Age */}
                    <td className="py-3 px-4 font-mono text-muted-foreground text-[11px]">
                      {agent.last_heartbeat ? (
                        <div className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-muted-foreground/70" />
                          <span>
                            {typeof agent.last_heartbeat_age_seconds === 'number'
                              ? `${agent.last_heartbeat_age_seconds}s ago`
                              : formatRelativeTime(agent.last_heartbeat)}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground/60 italic">No heartbeat</span>
                      )}
                    </td>

                    {/* Enrolled Date */}
                    <td className="py-3 px-4 text-muted-foreground text-[11px]">
                      {agent.created_at ? formatRelativeTime(agent.created_at) : '—'}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleOpenDetail(agent)}
                          className="h-8 px-2.5 text-xs text-muted-foreground hover:text-foreground"
                          title="Inspect agent telemetry"
                        >
                          <Info className="w-3.5 h-3.5 mr-1" />
                          Details
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigate(`/firewall?agent_id=${agent.id}`)}
                          className="h-8 px-2.5 text-xs gap-1 border-border/70 hover:border-primary/50 hover:text-primary"
                          title="Manage host firewall rules for this agent"
                        >
                          <Flame className="w-3.5 h-3.5 text-amber-500" />
                          Firewall
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination bar */}
          {totalAgents > limit && (
            <div className="p-3 border-t border-border/50 bg-muted/20 flex items-center justify-between text-xs text-muted-foreground">
              <div>
                Showing {offset + 1} to {Math.min(offset + limit, totalAgents)} of {totalAgents}
              </div>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                  className="h-7 px-2"
                >
                  <ChevronLeft className="w-3.5 h-3.5 mr-1" /> Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(offset + limit)}
                  disabled={offset + limit >= totalAgents}
                  className="h-7 px-2"
                >
                  Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────────────────────
          5. Slide-out Inspection Drawer (Agent Details)
      ───────────────────────────────────────────────────────────────────────────── */}
      <Drawer
        isOpen={Boolean(selectedAgent)}
        onClose={handleCloseDetail}
        title={selectedAgent?.hostname || 'Agent Telemetry'}
        subtitle={`Device UUID: ${selectedAgent?.id || ''}`}
        size="lg"
      >
        {selectedAgent && (
          <div className="space-y-6">
            {/* Status Summary Banner */}
            <div className="p-4 rounded-xl border border-border/60 bg-muted/30 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-lg bg-card border border-border/50">
                  {renderPlatformIcon(selectedAgent.platform, selectedAgent.os)}
                </div>
                <div>
                  <h4 className="text-sm font-semibold text-foreground">
                    {selectedAgent.hostname || 'Unregistered Host'}
                  </h4>
                  <div className="flex items-center gap-2 mt-0.5">
                    {renderStatusBadge(
                      agentStatusDetail?.status || selectedAgent.status,
                      agentStatusDetail?.last_heartbeat_age_seconds ?? selectedAgent.last_heartbeat_age_seconds
                    )}
                    <span className="text-xs text-muted-foreground font-mono">
                      v{selectedAgent.agent_version || '1.0.0'}
                    </span>
                  </div>
                </div>
              </div>

              <Button
                size="sm"
                variant="outline"
                onClick={() => navigate(`/firewall?agent_id=${selectedAgent.id}`)}
                className="gap-1.5 text-xs border-amber-500/30 text-amber-500 hover:bg-amber-500/10"
              >
                <Flame className="w-3.5 h-3.5" />
                Configure Firewall
              </Button>
            </div>

            {/* Error in detail fetch */}
            {detailError && (
              <Alert variant="destructive" className="py-2.5">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-xs ml-2">{detailError}</span>
              </Alert>
            )}

            {/* Telemetry Fields */}
            <div className="space-y-3">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground font-mono">
                System Telemetry
              </h5>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg border border-border/50 bg-card/60">
                  <span className="text-[11px] text-muted-foreground">Operating System</span>
                  <div className="text-xs font-medium text-foreground mt-0.5">
                    {agentStatusDetail?.os || selectedAgent.os || 'Unknown'}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60">
                  <span className="text-[11px] text-muted-foreground">Platform Architecture</span>
                  <div className="text-xs font-medium text-foreground mt-0.5 capitalize">
                    {agentStatusDetail?.platform || selectedAgent.platform || 'Unknown'}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60">
                  <span className="text-[11px] text-muted-foreground">Last Heartbeat</span>
                  <div className="text-xs font-medium text-foreground mt-0.5 font-mono">
                    {agentStatusDetail?.last_heartbeat
                      ? formatTimestamp(agentStatusDetail.last_heartbeat)
                      : selectedAgent.last_heartbeat
                      ? formatTimestamp(selectedAgent.last_heartbeat)
                      : 'Never'}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60">
                  <span className="text-[11px] text-muted-foreground">Heartbeat Latency</span>
                  <div className="text-xs font-medium text-foreground mt-0.5 font-mono">
                    {typeof (agentStatusDetail?.last_heartbeat_age_seconds ?? selectedAgent.last_heartbeat_age_seconds) ===
                    'number'
                      ? `${agentStatusDetail?.last_heartbeat_age_seconds ?? selectedAgent.last_heartbeat_age_seconds} seconds`
                      : 'Unknown'}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60 col-span-2">
                  <span className="text-[11px] text-muted-foreground">Enrolled Timestamp</span>
                  <div className="text-xs font-medium text-foreground mt-0.5 font-mono">
                    {selectedAgent.created_at ? formatTimestamp(selectedAgent.created_at) : 'Unknown'}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60 col-span-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-muted-foreground">Device Identifier (UUID)</span>
                    <button
                      onClick={() => copyToClipboard(selectedAgent.id, 'id', selectedAgent.id)}
                      className="text-[11px] text-primary hover:underline flex items-center gap-1 font-mono"
                    >
                      {copiedId === selectedAgent.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      Copy ID
                    </button>
                  </div>
                  <div className="text-xs font-mono text-muted-foreground mt-1 break-all">
                    {selectedAgent.id}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-border/50 bg-card/60 col-span-2">
                  <span className="text-[11px] text-muted-foreground">Organization Tenant ID</span>
                  <div className="text-xs font-mono text-muted-foreground mt-1 break-all">
                    {selectedAgent.organization_id}
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Actions & Notes */}
            <div className="p-3 rounded-lg border border-border/50 bg-muted/20 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <Info className="w-4 h-4 text-primary" />
                <span>Enterprise Agent Operations</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Agents poll the Gateway periodically for firewall instructions and safe-list updates. To enforce
                mitigations or block malicious IPs on this host, navigate to the Host Firewall console.
              </p>
              <div className="pt-2">
                <Button
                  size="sm"
                  onClick={() => navigate(`/firewall?agent_id=${selectedAgent.id}`)}
                  className="w-full gap-2 text-xs"
                >
                  <Flame className="w-4 h-4 text-amber-400" />
                  Open Host Firewall Console
                </Button>
              </div>
            </div>
          </div>
        )}
      </Drawer>

      {/* ─────────────────────────────────────────────────────────────────────────────
          6. Generate Enrollment Token Modal
      ───────────────────────────────────────────────────────────────────────────── */}
      <Dialog open={isTokenModalOpen} onOpenChange={setIsTokenModalOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-primary" />
              Enroll Enterprise Guard Agent
            </DialogTitle>
            <DialogDescription>
              Generate a single-use cryptographically signed token for bootstrapping a host daemon.
            </DialogDescription>
          </DialogHeader>

          {!generatedTokenData ? (
            <form onSubmit={handleGenerateToken} className="space-y-4 py-2">
              <div className="space-y-2">
                <label className="text-xs font-semibold text-foreground">Token Validity Duration</label>
                <select
                  value={validHours}
                  onChange={(e) => setValidHours(e.target.value)}
                  className="w-full h-9 text-xs rounded-md border border-input bg-background px-3 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value={12}>12 Hours</option>
                  <option value={24}>24 Hours (Recommended)</option>
                  <option value={48}>48 Hours</option>
                  <option value={72}>72 Hours</option>
                </select>
                <p className="text-[11px] text-muted-foreground">
                  The enrollment token will automatically expire if not redeemed within this timeframe.
                </p>
              </div>

              {tokenError && (
                <Alert variant="destructive" className="py-2.5">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-xs ml-2">{tokenError}</span>
                </Alert>
              )}

              <DialogFooter className="pt-2">
                <Button variant="outline" type="button" onClick={handleCloseTokenModal} disabled={isGeneratingToken}>
                  Cancel
                </Button>
                <Button type="submit" disabled={isGeneratingToken} className="gap-2">
                  {isGeneratingToken ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <Plus className="w-4 h-4" />
                      Generate Token
                    </>
                  )}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <div className="space-y-4 py-2">
              <Alert className="border-emerald-500/30 bg-emerald-500/10 py-3">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <div className="ml-2">
                  <h4 className="text-xs font-semibold text-emerald-400">Enrollment Token Active</h4>
                  <p className="text-[11px] text-emerald-500/80 mt-0.5">
                    Expires at: {formatTimestamp(generatedTokenData.expires_at)}
                  </p>
                </div>
              </Alert>

              {/* Monospace token container */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">One-Time Token</span>
                  <button
                    onClick={() => copyToClipboard(generatedTokenData.token, 'token')}
                    className="text-primary hover:underline flex items-center gap-1 font-mono text-[11px]"
                  >
                    {copiedToken ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    Copy Token
                  </button>
                </div>
                <div className="p-2.5 rounded-lg bg-muted/60 border border-border/70 font-mono text-xs break-all text-foreground select-all">
                  {generatedTokenData.token}
                </div>
              </div>

              {/* CLI command snippet */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Installation Command</span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        `cyberguard-agent --enroll ${generatedTokenData.token}`,
                        'command'
                      )
                    }
                    className="text-primary hover:underline flex items-center gap-1 font-mono text-[11px]"
                  >
                    {copiedCommand ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    Copy Command
                  </button>
                </div>
                <div className="p-3 rounded-lg bg-black/80 border border-border/80 font-mono text-xs text-emerald-400 break-all select-all flex items-center justify-between gap-2">
                  <span>cyberguard-agent --enroll {generatedTokenData.token}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg border border-border/60 bg-muted/30 text-[11px] text-muted-foreground leading-relaxed">
                <span className="font-semibold text-foreground">Single-use policy:</span> Upon the first successful
                handshake from the host daemon, the gateway will issue permanent cryptographic credentials and immediately
                invalidate this token.
              </div>

              <DialogFooter className="pt-2">
                <Button onClick={handleCloseTokenModal} className="w-full">
                  Done
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AgentsPage;
