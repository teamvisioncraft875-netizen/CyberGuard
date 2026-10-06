import React, { useState, useEffect, useCallback, useMemo } from 'react';
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
} from '../components/ui';
import {
  Flame,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Search,
  Filter,
  RotateCcw,
  Trash2,
  Copy,
  Check,
  Server,
  Globe,
  Laptop,
  Info,
  Lock,
  Plus,
  Terminal,
  Clock,
  ChevronRight,
  Shield,
  Layers,
} from 'lucide-react';
import { firewallService } from '../services/firewallService';
import { toast } from 'sonner';

export function FirewallPage({ onTriggerToast }) {
  const { user, isAdmin } = useAuth();

  // State: Rules and Pagination
  const [rules, setRules] = useState([]);
  const [rulesTotal, setRulesTotal] = useState(0);
  const [isLoadingRules, setIsLoadingRules] = useState(true);
  const [rulesError, setRulesError] = useState(null);

  // State: Enrolled Agents (Devices)
  const [agents, setAgents] = useState([]);
  const [isLoadingAgents, setIsLoadingAgents] = useState(true);

  // State: Protected Targets Baseline
  const [protectedTargets, setProtectedTargets] = useState(null);
  const [showProtectedModal, setShowProtectedModal] = useState(false);

  // State: Filters
  const [selectedAgentId, setSelectedAgentId] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all'); // all, active, pending, deleted
  const [typeFilter, setTypeFilter] = useState('all'); // all, block_ip, block_domain
  const [sourceFilter, setSourceFilter] = useState('all'); // all, manual, policy_engine
  const [searchQuery, setSearchQuery] = useState('');

  // State: Create Rule Dialog
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createAgentId, setCreateAgentId] = useState('');
  const [createRuleType, setCreateRuleType] = useState('block_ip'); // block_ip | block_domain
  const [createTargetValue, setCreateTargetValue] = useState('');
  const [isValidatingTarget, setIsValidatingTarget] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [isSubmittingRule, setIsSubmittingRule] = useState(false);
  const [createError, setCreateError] = useState(null);

  // State: Revoke Confirmation Dialog
  const [ruleToRevoke, setRuleToRevoke] = useState(null);
  const [isRevoking, setIsRevoking] = useState(false);

  // State: Copy feedback tracker
  const [copiedTargetId, setCopiedTargetId] = useState(null);

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Fetch Firewall Rules
  // ─────────────────────────────────────────────────────────────────────────────
  const fetchRules = useCallback(async () => {
    setIsLoadingRules(true);
    setRulesError(null);
    try {
      const params = { limit: 100, offset: 0 };
      if (selectedAgentId !== 'all') {
        params.agent_id = selectedAgentId;
      }
      if (statusFilter !== 'all') {
        params.status = statusFilter;
      }
      if (typeFilter !== 'all') {
        params.rule_type = typeFilter;
      }

      const res = await firewallService.listRules(params);
      setRules(res?.rules || []);
      setRulesTotal(res?.total || 0);
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to load firewall rules';
      setRulesError(msg);
      toast.error('Firewall Error', { description: msg });
    } finally {
      setIsLoadingRules(false);
    }
  }, [selectedAgentId, statusFilter, typeFilter]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Fetch Enrolled Agents (for device selector & hostname mapping)
  // ─────────────────────────────────────────────────────────────────────────────
  const fetchAgents = useCallback(async () => {
    setIsLoadingAgents(true);
    try {
      const res = await firewallService.listAgents({ limit: 100 });
      const agentList = res?.agents || [];
      setAgents(agentList);

      // Pre-select first agent in create dialog if not already set
      if (agentList.length > 0 && !createAgentId) {
        setCreateAgentId(agentList[0].id);
      }
    } catch (err) {
      console.warn('[FirewallPage] Could not load agents list:', err.message);
    } finally {
      setIsLoadingAgents(false);
    }
  }, [createAgentId]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Fetch Protected Network Targets
  // ─────────────────────────────────────────────────────────────────────────────
  const fetchProtectedTargets = useCallback(async () => {
    try {
      const data = await firewallService.getProtectedTargets();
      setProtectedTargets(data);
    } catch (err) {
      console.warn('[FirewallPage] Could not load protected targets:', err.message);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  useEffect(() => {
    fetchAgents();
    fetchProtectedTargets();
  }, [fetchAgents, fetchProtectedTargets]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Pre-Flight Target Validation
  // ─────────────────────────────────────────────────────────────────────────────
  const handleValidateTarget = async () => {
    const raw = createTargetValue.trim();
    if (!raw) {
      setValidationResult(null);
      setCreateError(null);
      return;
    }

    setIsValidatingTarget(true);
    setCreateError(null);

    const target_data =
      createRuleType === 'block_ip' ? { ip_address: raw } : { domain: raw };

    try {
      const res = await firewallService.validateRule({
        rule_type: createRuleType,
        target_data,
      });

      setValidationResult(res);
      if (!res.valid) {
        setCreateError(res.error_if_invalid || res.error || 'Target violates firewall policy');
      }
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Validation request failed';
      setValidationResult({ valid: false, error: msg });
      setCreateError(msg);
    } finally {
      setIsValidatingTarget(false);
    }
  };

  // Reset validation state when target input or rule type changes
  const handleTargetChange = (e) => {
    setCreateTargetValue(e.target.value);
    setValidationResult(null);
    setCreateError(null);
  };

  const handleRuleTypeChange = (newType) => {
    setCreateRuleType(newType);
    setCreateTargetValue('');
    setValidationResult(null);
    setCreateError(null);
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. Create Firewall Rule
  // ─────────────────────────────────────────────────────────────────────────────
  const handleCreateRuleSubmit = async (e) => {
    e.preventDefault();
    if (!createAgentId) {
      setCreateError('Please select a target enterprise agent device');
      return;
    }
    const cleanTarget = createTargetValue.trim();
    if (!cleanTarget) {
      setCreateError(
        createRuleType === 'block_ip'
          ? 'Valid IP address is required'
          : 'Valid domain name is required'
      );
      return;
    }

    setIsSubmittingRule(true);
    setCreateError(null);

    const target_data =
      createRuleType === 'block_ip'
        ? { ip_address: cleanTarget }
        : { domain: cleanTarget };

    try {
      const res = await firewallService.createRule({
        agent_id: createAgentId,
        rule_type: createRuleType,
        target_data,
      });

      toast.success('Firewall Rule Created', {
        description: `Rule for ${cleanTarget} queued to agent with status "${res.status}".`,
      });

      // Reset modal form
      setIsCreateOpen(false);
      setCreateTargetValue('');
      setValidationResult(null);
      setCreateError(null);

      // Refresh list immediately
      fetchRules();
    } catch (err) {
      const msg =
        err.response?.data?.error_message ||
        err.response?.data?.message ||
        err.message ||
        'Failed to create firewall rule';
      setCreateError(msg);
      toast.error('Rule Creation Failed', { description: msg });
    } finally {
      setIsSubmittingRule(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. Revoke Firewall Rule
  // ─────────────────────────────────────────────────────────────────────────────
  const handleConfirmRevoke = async () => {
    if (!ruleToRevoke) return;

    setIsRevoking(true);
    try {
      const res = await firewallService.deleteRule(ruleToRevoke.id);
      toast.success('Revocation Initiated', {
        description: `Rule ${ruleToRevoke.target} marked as "${res.status}". Agent unblock command dispatched.`,
      });

      setRuleToRevoke(null);
      fetchRules();
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to revoke firewall rule';
      toast.error('Revocation Failed', { description: msg });
    } finally {
      setIsRevoking(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 7. Clipboard copy
  // ─────────────────────────────────────────────────────────────────────────────
  const handleCopyTarget = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedTargetId(id);
    setTimeout(() => setCopiedTargetId(null), 2000);
    toast.info('Copied to clipboard', { description: text });
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 8. Derived Metrics and Filtering
  // ─────────────────────────────────────────────────────────────────────────────
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      // Search query matches target, agent hostname, or local rule id
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const targetMatch = rule.target?.toLowerCase().includes(q);
        const agentMatch = rule.agent_name?.toLowerCase().includes(q);
        const localIdMatch = rule.rule_id_local?.toLowerCase().includes(q);
        const creatorMatch = rule.created_by?.toLowerCase().includes(q);
        if (!targetMatch && !agentMatch && !localIdMatch && !creatorMatch) {
          return false;
        }
      }

      // Source filter
      if (sourceFilter !== 'all' && rule.source !== sourceFilter) {
        return false;
      }

      return true;
    });
  }, [rules, searchQuery, sourceFilter]);

  const activeCount = useMemo(
    () => rules.filter((r) => r.status === 'active').length,
    [rules]
  );
  const pendingCount = useMemo(
    () => rules.filter((r) => r.status === 'pending').length,
    [rules]
  );
  const revokingCount = useMemo(
    () => rules.filter((r) => r.status === 'pending_delete' || r.status === 'deleted').length,
    [rules]
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // 9. Status Helpers
  // ─────────────────────────────────────────────────────────────────────────────
  const renderStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Active
          </span>
        );
      case 'pending':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
            Pending Enforcement
          </span>
        );
      case 'pending_delete':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
            Revocation Pending
          </span>
        );
      case 'deleted':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-muted text-muted-foreground border border-border">
            <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />
            Revoked
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-muted text-muted-foreground">
            {status}
          </span>
        );
    }
  };

  // Non-admin fallback view
  if (!isAdmin) {
    return (
      <div className="space-y-6 max-w-4xl mx-auto py-12 px-4">
        <Alert variant="destructive">
          <ShieldAlert className="w-5 h-5" />
          <div className="space-y-1">
            <h3 className="font-semibold text-sm">Administrator Access Required</h3>
            <p className="text-xs">
              Host Firewall and Network Protection is restricted to organization administrators.
              Contact your system administrator for elevated privileges.
            </p>
          </div>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-[1600px] mx-auto w-full pb-16 font-sans">
      {/* ─────────────────────────────────────────────────────────────────────────────
          1. Header Section
          ───────────────────────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-border">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/25 flex items-center justify-center text-primary shadow-sm">
              <Flame className="w-5 h-5 text-amber-500" />
            </div>
            <div>
              <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
                Host Firewall & Network Protection
              </h1>
              <p className="font-body text-xs text-muted-foreground">
                Enforce host-level IP and domain blocking policies across enterprise agent fleet
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Organization context badge */}
          {user?.organization_id && (
            <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-muted/60 border border-border text-xs font-mono text-muted-foreground">
              <Server className="w-3.5 h-3.5 text-primary" />
              <span>Org:</span>
              <span className="font-bold text-foreground">
                {user.organization_id.slice(0, 8)}...
              </span>
            </div>
          )}

          {/* Safety Baseline Trigger */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowProtectedModal(true)}
            icon={<Shield className="w-4 h-4 text-emerald-500" />}
            className="text-xs"
          >
            Protected Targets
          </Button>

          {/* Refresh Trigger */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              fetchRules();
              fetchAgents();
            }}
            isLoading={isLoadingRules}
            icon={<RotateCcw className="w-4 h-4" />}
            title="Refresh rules and agent status"
            className="text-xs"
          >
            Refresh
          </Button>

          {/* Create Rule Trigger */}
          <Button
            variant="default"
            size="sm"
            onClick={() => {
              setIsCreateOpen(true);
              setCreateError(null);
              setValidationResult(null);
            }}
            icon={<Plus className="w-4 h-4" />}
            className="text-xs font-semibold"
          >
            Add Firewall Rule
          </Button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          2. Metrics Summary Strip
          ───────────────────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {/* Total Rules */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span>Total Rules</span>
            <Layers className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground">{rulesTotal}</div>
          <p className="text-[11px] text-muted-foreground">Managed fleet policies</p>
        </div>

        {/* Active Rules */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span>Active Enforced</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{activeCount}</div>
          <p className="text-[11px] text-muted-foreground">Locally applied on agents</p>
        </div>

        {/* Pending Enforcement */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span>Pending Enforcement</span>
            <Clock className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{pendingCount}</div>
          <p className="text-[11px] text-muted-foreground">Queued in agent pipeline</p>
        </div>

        {/* Enrolled Agents */}
        <div className="p-4 rounded-xl bg-card border border-border space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span>Enrolled Agents</span>
            <Laptop className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-foreground">{agents.length}</div>
          <p className="text-[11px] text-muted-foreground">Connected host daemons</p>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          3. Filters & Search Toolbar
          ───────────────────────────────────────────────────────────────────────────── */}
      <div className="p-4 rounded-xl bg-card border border-border space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by target IP, domain, hostname, or rule ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-muted/40 border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Quick Filters */}
          <div className="flex flex-wrap items-center gap-2.5 text-xs">
            {/* Agent Device Selector */}
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground text-[11px]">Agent:</span>
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-muted/60 border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="all">All Enterprise Agents ({agents.length})</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.hostname || agent.id.slice(0, 8)} ({agent.platform || 'host'})
                  </option>
                ))}
              </select>
            </div>

            {/* Rule Type Selector */}
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground text-[11px]">Type:</span>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-muted/60 border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="all">All Types</option>
                <option value="block_ip">Block IP</option>
                <option value="block_domain">Block Domain</option>
              </select>
            </div>

            {/* Source Origin Selector */}
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground text-[11px]">Source:</span>
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-muted/60 border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="all">All Origins</option>
                <option value="manual">Manual (Admin)</option>
                <option value="policy_engine">Automated Policy</option>
              </select>
            </div>
          </div>
        </div>

        {/* Status Tab Navigation */}
        <div className="flex items-center gap-1 pt-2 border-t border-border overflow-x-auto text-xs">
          {[
            { id: 'all', label: 'All Rules', count: rules.length },
            { id: 'active', label: 'Active', count: activeCount },
            { id: 'pending', label: 'Pending Enforcement', count: pendingCount },
            { id: 'deleted', label: 'Revoked', count: revokingCount },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setStatusFilter(tab.id)}
              className={cn(
                'px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-2 whitespace-nowrap',
                statusFilter === tab.id
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
              )}
            >
              <span>{tab.label}</span>
              <span
                className={cn(
                  'px-1.5 py-0.5 rounded text-[10px] font-mono',
                  statusFilter === tab.id
                    ? 'bg-primary-foreground/20 text-primary-foreground'
                    : 'bg-muted text-muted-foreground'
                )}
              >
                {tab.count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          4. Firewall Rules Table / Content Area
          ───────────────────────────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-card border border-border overflow-hidden">
        {/* Error state */}
        {rulesError && (
          <div className="p-6">
            <Alert variant="destructive">
              <AlertTriangle className="w-4 h-4" />
              <div className="flex-1 space-y-1">
                <p className="font-semibold text-xs">Failed to load firewall rules</p>
                <p className="text-xs">{rulesError}</p>
              </div>
              <Button variant="outline" size="sm" onClick={fetchRules} className="text-xs shrink-0">
                Try Again
              </Button>
            </Alert>
          </div>
        )}

        {/* Loading state */}
        {isLoadingRules && !rulesError && (
          <div className="p-8 space-y-4">
            <div className="flex items-center justify-center gap-3 py-12 text-muted-foreground text-xs">
              <span className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
              <span>Querying host firewall policies from gateway...</span>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!isLoadingRules && !rulesError && filteredRules.length === 0 && (
          <div className="p-8">
            <EmptyState
              icon={Flame}
              title={
                rules.length === 0
                  ? 'No Host Firewall Rules Configured'
                  : 'No Rules Match Active Filters'
              }
              description={
                rules.length === 0
                  ? 'Deploy IP and domain blocking policies to enterprise agents to isolate active threats.'
                  : 'Adjust your search query or reset filter parameters to inspect matching firewall policies.'
              }
              actionLabel={rules.length === 0 ? 'Add Firewall Rule' : 'Clear Filters'}
              onAction={
                rules.length === 0
                  ? () => setIsCreateOpen(true)
                  : () => {
                      setSearchQuery('');
                      setSelectedAgentId('all');
                      setStatusFilter('all');
                      setTypeFilter('all');
                      setSourceFilter('all');
                    }
              }
            />
          </div>
        )}

        {/* Rules Table (Desktop view) */}
        {!isLoadingRules && !rulesError && filteredRules.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/40 border-b border-border text-[11px] font-mono text-muted-foreground uppercase">
                <tr>
                  <th className="px-4 py-3 font-semibold">Target & Type</th>
                  <th className="px-4 py-3 font-semibold">Target Agent</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold">Origin</th>
                  <th className="px-4 py-3 font-semibold">Host Identifier</th>
                  <th className="px-4 py-3 font-semibold">Created</th>
                  <th className="px-4 py-3 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filteredRules.map((rule) => {
                  const isPendingDelete = rule.status === 'pending_delete';
                  const isDeleted = rule.status === 'deleted';
                  const isActionable = !isPendingDelete && !isDeleted;

                  return (
                    <tr
                      key={rule.id}
                      className={cn(
                        'hover:bg-muted/30 transition-colors',
                        (isPendingDelete || isDeleted) && 'opacity-60 bg-muted/10'
                      )}
                    >
                      {/* 1. Target & Type */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              'px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase shrink-0',
                              rule.rule_type === 'block_ip'
                                ? 'bg-amber-500/15 text-amber-500 border border-amber-500/30'
                                : 'bg-sky-500/15 text-sky-500 border border-sky-500/30'
                            )}
                          >
                            {rule.rule_type === 'block_ip' ? 'IP' : 'Domain'}
                          </span>
                          <span className="font-mono font-bold text-foreground text-xs truncate max-w-[220px]">
                            {rule.target}
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopyTarget(rule.target, rule.id)}
                            className="text-muted-foreground hover:text-foreground shrink-0 p-1"
                            title="Copy target"
                          >
                            {copiedTargetId === rule.id ? (
                              <Check className="w-3 h-3 text-emerald-500" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* 2. Target Agent */}
                      <td className="px-4 py-3.5">
                        <div className="space-y-0.5">
                          <div className="font-medium text-foreground flex items-center gap-1.5">
                            <Laptop className="w-3.5 h-3.5 text-muted-foreground" />
                            <span className="font-mono text-xs">{rule.agent_name || 'Agent'}</span>
                          </div>
                          <div className="text-[11px] font-mono text-muted-foreground">
                            {rule.agent_id ? rule.agent_id.slice(0, 8) : 'Unknown ID'}
                          </div>
                        </div>
                      </td>

                      {/* 3. Status */}
                      <td className="px-4 py-3.5">{renderStatusBadge(rule.status)}</td>

                      {/* 4. Origin */}
                      <td className="px-4 py-3.5">
                        {rule.source === 'policy_engine' ? (
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/30">
                              <ShieldAlert className="w-3 h-3" />
                              Policy Engine
                            </span>
                            {rule.source_command_id && (
                              <div className="text-[10px] font-mono text-muted-foreground">
                                Cmd: {rule.source_command_id.slice(0, 8)}
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30">
                              Manual
                            </span>
                            {rule.created_by && (
                              <div className="text-[10px] font-mono text-muted-foreground truncate max-w-[140px]">
                                {rule.created_by}
                              </div>
                            )}
                          </div>
                        )}
                      </td>

                      {/* 5. Host Identifier */}
                      <td className="px-4 py-3.5 font-mono text-[11px] text-muted-foreground">
                        {rule.rule_id_local ? (
                          <span
                            title={rule.rule_id_local}
                            className="bg-muted px-1.5 py-0.5 rounded truncate block max-w-[160px]"
                          >
                            {rule.rule_id_local}
                          </span>
                        ) : (
                          <span className="text-muted-foreground/60 italic">pending sync</span>
                        )}
                      </td>

                      {/* 6. Created */}
                      <td className="px-4 py-3.5 font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                        <span title={formatTimestamp(rule.created_at)}>
                          {formatRelativeTime(rule.created_at)}
                        </span>
                      </td>

                      {/* 7. Actions */}
                      <td className="px-4 py-3.5 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={!isActionable}
                          onClick={() => setRuleToRevoke(rule)}
                          className={cn(
                            'h-7 px-2.5 text-xs font-semibold',
                            isActionable
                              ? 'text-destructive hover:bg-destructive/10 hover:text-destructive'
                              : 'text-muted-foreground'
                          )}
                          icon={<Trash2 className="w-3.5 h-3.5" />}
                        >
                          Revoke
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          5. Add Firewall Rule Modal Dialog
          ───────────────────────────────────────────────────────────────────────────── */}
      <Dialog open={isCreateOpen} onOpenChange={(open) => !isSubmittingRule && setIsCreateOpen(open)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Flame className="w-5 h-5 text-amber-500" />
              Add Host Firewall Rule
            </DialogTitle>
            <DialogDescription className="text-xs">
              Enforce a network boundary block rule on an enrolled enterprise agent.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateRuleSubmit} className="space-y-4 pt-2">
            {/* 1. Target Agent Device */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground flex items-center justify-between">
                <span>Target Enterprise Agent</span>
                <span className="text-[11px] text-muted-foreground font-mono">
                  {agents.length} enrolled
                </span>
              </label>
              {isLoadingAgents ? (
                <div className="p-2.5 rounded-lg border border-border bg-muted/30 text-xs text-muted-foreground flex items-center gap-2">
                  <span className="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Loading enrolled agents...
                </div>
              ) : agents.length === 0 ? (
                <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs text-amber-400">
                  No enrolled enterprise agents found in your organization. An agent must be enrolled
                  before host firewall rules can be applied.
                </div>
              ) : (
                <select
                  value={createAgentId}
                  onChange={(e) => {
                    setCreateAgentId(e.target.value);
                    setValidationResult(null);
                    setCreateError(null);
                  }}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-card border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname || 'Host'} ({agent.platform || 'os'}) — Status: {agent.status}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* 2. Rule Type Toggle */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground">Rule Type</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => handleRuleTypeChange('block_ip')}
                  className={cn(
                    'p-3 rounded-lg border text-left transition-all space-y-1',
                    createRuleType === 'block_ip'
                      ? 'border-primary bg-primary/10 ring-1 ring-primary'
                      : 'border-border bg-card hover:bg-muted/40'
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-amber-500" />
                    <span className="text-xs font-semibold text-foreground">Block IP Address</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Block inbound/outbound packets to a specific IPv4/IPv6 address.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleRuleTypeChange('block_domain')}
                  className={cn(
                    'p-3 rounded-lg border text-left transition-all space-y-1',
                    createRuleType === 'block_domain'
                      ? 'border-primary bg-primary/10 ring-1 ring-primary'
                      : 'border-border bg-card hover:bg-muted/40'
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-sky-500" />
                    <span className="text-xs font-semibold text-foreground">Block Domain</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    Block DNS resolution and connections to a fully qualified domain name.
                  </p>
                </button>
              </div>
            </div>

            {/* 3. Target Input & Pre-Flight Validation */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-foreground">
                  {createRuleType === 'block_ip' ? 'Target IP Address' : 'Target Domain Name'}
                </label>
                <button
                  type="button"
                  onClick={handleValidateTarget}
                  disabled={!createTargetValue.trim() || isValidatingTarget}
                  className="text-[11px] font-mono text-primary hover:underline disabled:opacity-50"
                >
                  {isValidatingTarget ? 'Validating...' : 'Pre-flight check'}
                </button>
              </div>

              <div className="relative">
                <input
                  type="text"
                  placeholder={
                    createRuleType === 'block_ip'
                      ? 'e.g. 198.51.100.24 or 203.0.113.88'
                      : 'e.g. c2-command.badsite.com'
                  }
                  value={createTargetValue}
                  onChange={handleTargetChange}
                  onBlur={handleValidateTarget}
                  required
                  className="w-full px-3 py-2 rounded-lg bg-card border border-border text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <p className="text-[11px] text-muted-foreground">
                {createRuleType === 'block_ip'
                  ? 'Must be a valid public IP. Private RFC 1918 subnets, loopbacks, and DNS resolvers are protected.'
                  : 'Must be a valid FQDN. Wildcards (*), protocols (http://), and localhost are protected.'}
              </p>
            </div>

            {/* Pre-flight validation banner */}
            {validationResult && validationResult.valid && (
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>Target is valid and confirmed safe to block.</span>
              </div>
            )}

            {/* Error banner */}
            {createError && (
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-xs text-destructive flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <p className="font-semibold">Target validation failed</p>
                  <p className="leading-relaxed">{createError}</p>
                </div>
              </div>
            )}

            {/* Form actions */}
            <DialogFooter className="pt-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setIsCreateOpen(false)}
                disabled={isSubmittingRule}
                className="text-xs"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="default"
                size="sm"
                disabled={
                  isSubmittingRule ||
                  !createTargetValue.trim() ||
                  !createAgentId ||
                  (validationResult && !validationResult.valid)
                }
                isLoading={isSubmittingRule}
                className="text-xs font-semibold"
              >
                Enforce Rule
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ─────────────────────────────────────────────────────────────────────────────
          6. Revoke Confirmation Modal Dialog
          ───────────────────────────────────────────────────────────────────────────── */}
      <Dialog open={Boolean(ruleToRevoke)} onOpenChange={(open) => !isRevoking && setRuleToRevoke(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base text-destructive">
              <AlertTriangle className="w-5 h-5 text-destructive" />
              Revoke Firewall Rule
            </DialogTitle>
            <DialogDescription className="text-xs">
              This will unblock network traffic for the specified target on the host agent.
            </DialogDescription>
          </DialogHeader>

          {ruleToRevoke && (
            <div className="space-y-3 pt-2 text-xs">
              <div className="p-3 rounded-lg bg-muted/40 border border-border space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Target:</span>
                  <span className="font-bold text-foreground">{ruleToRevoke.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type:</span>
                  <span className="capitalize">{ruleToRevoke.rule_type?.replace(/_/g, ' ')}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Agent:</span>
                  <span>{ruleToRevoke.agent_name || ruleToRevoke.agent_id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Rule ID:</span>
                  <span className="truncate max-w-[180px]">{ruleToRevoke.id}</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-400">
                An asynchronous revocation command will be dispatched to the host agent. The rule will
                transition to <strong>pending_delete</strong> until the agent completes local unblocking.
              </div>
            </div>
          )}

          <DialogFooter className="pt-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setRuleToRevoke(null)}
              disabled={isRevoking}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={handleConfirmRevoke}
              isLoading={isRevoking}
              className="text-xs font-semibold"
            >
              Confirm Revocation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ─────────────────────────────────────────────────────────────────────────────
          7. Protected Targets Safety Baseline Modal
          ───────────────────────────────────────────────────────────────────────────── */}
      <Dialog open={showProtectedModal} onOpenChange={setShowProtectedModal}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Shield className="w-5 h-5 text-emerald-500" />
              Protected Network Boundaries
            </DialogTitle>
            <DialogDescription className="text-xs">
              Hardcoded safety baselines preventing enterprise network isolation and gateway lockouts.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 pt-2 text-xs">
            <p className="text-muted-foreground leading-relaxed">
              CyberGuard automatically rejects firewall rules targeting essential network infrastructure,
              RFC 1918 private subnets, loopbacks, and core DNS resolvers.
            </p>

            {/* Protected IP Ranges */}
            <div className="space-y-1.5">
              <h4 className="font-semibold text-foreground flex items-center gap-1.5">
                <Server className="w-4 h-4 text-primary" />
                Protected Private & Reserved IPv4 Subnets
              </h4>
              <div className="p-3 rounded-lg bg-muted/40 border border-border font-mono text-[11px] grid grid-cols-2 sm:grid-cols-3 gap-2">
                {protectedTargets?.protected_ip_ranges?.map((cidr) => (
                  <span key={cidr} className="px-2 py-1 rounded bg-muted text-foreground">
                    {cidr}
                  </span>
                )) || (
                  <>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">127.0.0.0/8</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">10.0.0.0/8</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">172.16.0.0/12</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">192.168.0.0/16</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">169.254.0.0/16</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">0.0.0.0/8</span>
                  </>
                )}
              </div>
            </div>

            {/* Protected Public Resolvers & Static IPs */}
            <div className="space-y-1.5">
              <h4 className="font-semibold text-foreground flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-emerald-500" />
                Protected Public DNS Resolvers & Endpoints
              </h4>
              <div className="p-3 rounded-lg bg-muted/40 border border-border font-mono text-[11px] flex flex-wrap gap-2">
                {protectedTargets?.protected_ips?.map((ip) => (
                  <span key={ip} className="px-2 py-1 rounded bg-muted text-foreground">
                    {ip}
                  </span>
                )) || (
                  <>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">127.0.0.1</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">8.8.8.8</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">8.8.4.4</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">1.1.1.1</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">1.0.0.1</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">9.9.9.9</span>
                  </>
                )}
              </div>
            </div>

            {/* Protected Domains */}
            <div className="space-y-1.5">
              <h4 className="font-semibold text-foreground flex items-center gap-1.5">
                <Lock className="w-4 h-4 text-sky-500" />
                Protected Core Domains
              </h4>
              <div className="p-3 rounded-lg bg-muted/40 border border-border font-mono text-[11px] flex flex-wrap gap-2">
                {protectedTargets?.protected_domains?.map((domain) => (
                  <span key={domain} className="px-2 py-1 rounded bg-muted text-foreground">
                    {domain}
                  </span>
                )) || (
                  <>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">localhost</span>
                    <span className="px-2 py-1 rounded bg-muted text-foreground">cyberguard.local</span>
                  </>
                )}
              </div>
            </div>
          </div>

          <DialogFooter className="pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setShowProtectedModal(false)}
              className="text-xs"
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default FirewallPage;
