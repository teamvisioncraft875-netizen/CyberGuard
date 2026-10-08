import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { useSocket } from '../hooks/useSocket';
import { useAuth } from '../context/AuthContext';
import { cn } from '../utils/cn';
import { normalizeRisk } from '../utils/risk';
import { normalizeAction } from '../utils/actions';
import { formatRelativeTime, formatTimestamp, truncate } from '../utils/format';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
  RiskBadge,
  Badge,
  Button,
  Drawer,
  EmptyState,
  Select,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
} from '../components/ui';
import { incidentService } from '../services';
import {
  ShieldAlert,
  Search,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
  Check,
  Copy,
  AlertCircle,
  RefreshCw,
  Shield,
  FileText,
  GitBranch,
  Network,
  UserCheck,
  Flame,
  CheckCircle,
  Activity,
  ArrowRight,
  Send,
  Crosshair,
  Clock,
  Layers,
  Laptop,
} from 'lucide-react';

/**
 * 7 Authoritative Threat Types from types.ts
 */
const THREAT_TYPES = [
  { value: 'phishing', label: 'Phishing' },
  { value: 'malicious_url', label: 'Malicious URL' },
  { value: 'deepfake', label: 'Deepfake' },
  { value: 'impersonation', label: 'Impersonation' },
  { value: 'account_takeover', label: 'Account Takeover' },
  { value: 'technical_threat', label: 'Technical Threat' },
  { value: 'system_anomaly', label: 'System Anomaly' },
];

const MITRE_TACTIC_NAMES = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0004: 'Privilege Escalation',
  TA0011: 'Command & Control',
};

function formatThreatType(threatType) {
  const match = THREAT_TYPES.find((t) => t.value === threatType);
  if (match) return match.label;
  return threatType ? threatType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Unknown';
}

function getTimelineBadge(eventType) {
  switch (eventType) {
    case 'incident_created':
      return { label: 'Incident Created', icon: ShieldAlert, color: 'text-rose-500 bg-rose-500/10 border-rose-500/30' };
    case 'detection_signal':
      return { label: 'Signal', icon: Activity, color: 'text-sky-500 bg-sky-500/10 border-sky-500/30' };
    case 'ioc_matched':
      return { label: 'IOC Match', icon: Crosshair, color: 'text-amber-500 bg-amber-500/10 border-amber-500/30' };
    case 'correlation_linked':
      return { label: 'Correlated', icon: Network, color: 'text-violet-500 bg-violet-500/10 border-violet-500/30' };
    case 'group_assigned':
      return { label: 'Campaign', icon: Layers, color: 'text-indigo-500 bg-indigo-500/10 border-indigo-500/30' };
    case 'attack_chain_step':
      return { label: 'Attack Stage', icon: GitBranch, color: 'text-purple-500 bg-purple-500/10 border-purple-500/30' };
    case 'analyst_note':
      return { label: 'Analyst Note', icon: FileText, color: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30' };
    case 'audit_event':
      return { label: 'Audit Trail', icon: Clock, color: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/30' };
    default:
      return { label: 'Event', icon: Activity, color: 'text-muted-foreground bg-muted border-border' };
  }
}

export function IncidentsPage() {
  // Remote server data states
  const [incidents, setIncidents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState(null);

  // Filters (server-side query params)
  const [riskFilter, setRiskFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [threatFilter, setThreatFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Pagination (server-side limit/offset)
  const limit = 10;
  const [offset, setOffset] = useState(0);

  const { user } = useAuth();

  // Detail Drawer state
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [activeIncident, setActiveIncident] = useState(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [isDrawerLoading, setIsDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState(null);
  const [copiedId, setCopiedId] = useState(false);

  // SOC Investigation tabs and panels
  const [activeTab, setActiveTab] = useState('overview');

  // Investigation Workspace state (GET /api/v1/incidents/:id/workspace)
  const [workspaceData, setWorkspaceData] = useState(null);
  const [isWorkspaceLoading, setIsWorkspaceLoading] = useState(false);
  const [workspaceError, setWorkspaceError] = useState(null);

  // Attack Chain state (GET /api/v1/incidents/:id/attack-chain & /graph)
  const [attackChainData, setAttackChainData] = useState(null);
  const [attackChainGraph, setAttackChainGraph] = useState(null);
  const [isAttackChainLoading, setIsAttackChainLoading] = useState(false);
  const [attackChainError, setAttackChainError] = useState(null);

  // Related Incidents state (GET /api/v1/incidents/:id/related)
  const [relatedData, setRelatedData] = useState(null);
  const [isRelatedLoading, setIsRelatedLoading] = useState(false);
  const [relatedError, setRelatedError] = useState(null);

  // Append-only Notes state (POST /api/v1/incidents/:id/notes)
  const [newNoteText, setNewNoteText] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);
  const [noteFeedback, setNoteFeedback] = useState(null);

  // Analyst Action state
  const [actionLoading, setActionLoading] = useState(null);
  const [actionFeedback, setActionFeedback] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [dialogReason, setDialogReason] = useState('');

  // Fetch incidents list from GET /api/v1/incidents
  const fetchIncidents = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);

    try {
      const res = await incidentService.listIncidents({
        limit,
        offset,
        risk_level: riskFilter,
        status: statusFilter,
        threat_type: threatFilter,
      });

      setIncidents(res.incidents || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      if (err.status === 429 || err.code === 'RATE_LIMITED') {
        setApiError('Too many requests. Please wait a few minutes.');
      } else {
        setApiError(err.message || 'Unable to retrieve incidents from gateway database.');
      }
    } finally {
      setIsLoading(false);
    }
  }, [limit, offset, riskFilter, statusFilter, threatFilter]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const { onIncident } = useSocket();
  const [highlightedIncidentId, setHighlightedIncidentId] = useState(null);
  const tableContainerRef = useRef(null);

  // Live real-time socket listener: prepend incoming incident live (no refresh needed)
  useEffect(() => {
    const unsubscribe = onIncident((newIncident) => {
      if (!newIncident || !newIncident.id) return;
      setIncidents((prev) => {
        if (prev.some((item) => item.id === newIncident.id)) {
          return prev;
        }
        return [newIncident, ...prev];
      });
      setTotalCount((prev) => prev + 1);
      setHighlightedIncidentId(newIncident.id);
    });

    return unsubscribe;
  }, [onIncident]);

  // Subtle GSAP highlight on newly prepended row: under 500ms, settles to normal styling
  useGSAP(
    () => {
      if (!highlightedIncidentId) return;
      const rowEl = tableContainerRef.current?.querySelector(
        `[data-incident-id="${highlightedIncidentId}"]`
      );
      if (rowEl) {
        gsap.fromTo(
          rowEl,
          { backgroundColor: 'rgba(56, 189, 248, 0.35)' },
          {
            backgroundColor: 'transparent',
            duration: 0.45,
            ease: 'power2.out',
            clearProps: 'backgroundColor',
            onComplete: () => {
              setHighlightedIncidentId(null);
            },
          }
        );
      }
    },
    { dependencies: [highlightedIncidentId], scope: tableContainerRef }
  );

  // Load full workspace details (GET /api/v1/incidents/:id/workspace)
  const loadWorkspace = useCallback(async (id) => {
    if (!id) return;
    setIsWorkspaceLoading(true);
    setWorkspaceError(null);
    try {
      const data = await incidentService.getWorkspace(id);
      setWorkspaceData(data);
    } catch (err) {
      setWorkspaceError(err.message || 'Failed to load investigation workspace');
    } finally {
      setIsWorkspaceLoading(false);
    }
  }, []);

  // Load attack chain progression and graph (GET /api/v1/incidents/:id/attack-chain & /graph)
  const loadAttackChain = useCallback(async (id) => {
    if (!id) return;
    setIsAttackChainLoading(true);
    setAttackChainError(null);
    try {
      const [chain, graph] = await Promise.all([
        incidentService.getAttackChain(id).catch((err) => {
          console.warn('[AttackChain Timeline Notice]', err.message);
          return null;
        }),
        incidentService.getAttackChainGraph(id).catch((err) => {
          console.warn('[AttackChain Graph Notice]', err.message);
          return null;
        }),
      ]);
      setAttackChainData(chain);
      setAttackChainGraph(graph);
    } catch (err) {
      setAttackChainError(err.message || 'Failed to load attack chain');
    } finally {
      setIsAttackChainLoading(false);
    }
  }, []);

  // Load related incidents (GET /api/v1/incidents/:id/related)
  const loadRelated = useCallback(async (id) => {
    if (!id) return;
    setIsRelatedLoading(true);
    setRelatedError(null);
    try {
      const data = await incidentService.getRelatedIncidents(id);
      setRelatedData(data);
    } catch (err) {
      setRelatedError(err.message || 'Failed to load related incidents');
    } finally {
      setIsRelatedLoading(false);
    }
  }, []);

  // Fetch single incident details for detail drawer
  const handleOpenIncident = async (incident) => {
    setSelectedIncidentId(incident.id);
    setIsDrawerOpen(true);
    setIsDrawerLoading(true);
    setDrawerError(null);
    setWorkspaceData(null);
    setAttackChainData(null);
    setAttackChainGraph(null);
    setRelatedData(null);
    setNoteFeedback(null);
    setActionFeedback(null);

    try {
      const data = await incidentService.getIncident(incident.id);
      setActiveIncident(data);

      // Pre-load tab-specific data if user is already inspecting a non-overview tab
      if (activeTab === 'investigation') {
        loadWorkspace(incident.id);
      } else if (activeTab === 'attack-chain') {
        loadAttackChain(incident.id);
      } else if (activeTab === 'related') {
        loadRelated(incident.id);
      }
    } catch (err) {
      // If single incident fetch fails, fall back to the summary row
      setActiveIncident(incident);
      if (err.status !== 404) {
        setDrawerError(err.message);
      }
    } finally {
      setIsDrawerLoading(false);
    }
  };

  // Switch drawer seamlessly to inspect a related incident or graph node
  const handleOpenIncidentById = async (targetId) => {
    if (!targetId) return;
    setSelectedIncidentId(targetId);
    setIsDrawerLoading(true);
    setDrawerError(null);
    setWorkspaceData(null);
    setAttackChainData(null);
    setAttackChainGraph(null);
    setRelatedData(null);
    setNoteFeedback(null);
    setActionFeedback(null);

    try {
      const data = await incidentService.getIncident(targetId);
      setActiveIncident(data);

      if (activeTab === 'investigation') {
        loadWorkspace(targetId);
      } else if (activeTab === 'attack-chain') {
        loadAttackChain(targetId);
      } else if (activeTab === 'related') {
        loadRelated(targetId);
      }
    } catch (err) {
      setDrawerError(err.message || 'Failed to load incident details');
    } finally {
      setIsDrawerLoading(false);
    }
  };

  // Append-only Note submission (POST /api/v1/incidents/:id/notes)
  const handleAddNote = async (e) => {
    e?.preventDefault();
    if (!newNoteText.trim() || !activeIncident?.id) return;
    setIsSubmittingNote(true);
    setNoteFeedback(null);
    try {
      const createdNote = await incidentService.addNote(activeIncident.id, newNoteText.trim());
      setNewNoteText('');
      setNoteFeedback({ type: 'success', message: 'Note added successfully.' });

      // Append new note to active workspace state
      setWorkspaceData((prev) => {
        if (!prev) return prev;
        const currentNotes = prev.notes || [];
        return {
          ...prev,
          notes: [...currentNotes, createdNote],
        };
      });
      setTimeout(() => setNoteFeedback(null), 3000);
    } catch (err) {
      setNoteFeedback({ type: 'error', message: err.message || 'Failed to record note.' });
    } finally {
      setIsSubmittingNote(false);
    }
  };

  // Assign incident to authenticated user (POST /api/v1/incidents/:id/assign)
  const handleAssignToMe = async () => {
    if (!activeIncident?.id || !user?.id) {
      setActionFeedback({ type: 'error', message: 'User identity is not available to assign.' });
      return;
    }
    setActionLoading('assign');
    setActionFeedback(null);
    try {
      const updated = await incidentService.assignIncident(activeIncident.id, user.id);
      setActiveIncident((prev) => ({
        ...prev,
        assigned_to: user.id,
        assigned_user_email: user.email,
        assigned_at: updated?.assigned_at || new Date().toISOString(),
      }));
      setIncidents((prev) =>
        prev.map((i) =>
          i.id === activeIncident.id
            ? { ...i, assigned_to: user.id, assigned_user_email: user.email }
            : i
        )
      );
      if (workspaceData?.incident) {
        setWorkspaceData((prev) => ({
          ...prev,
          incident: {
            ...prev.incident,
            assigned_to: user.id,
            assigned_user_email: user.email,
          },
        }));
      }
      setActionFeedback({ type: 'success', message: 'Incident assigned to you.' });
      setTimeout(() => setActionFeedback(null), 3000);
    } catch (err) {
      setActionFeedback({ type: 'error', message: err.message || 'Failed to assign incident' });
    } finally {
      setActionLoading(null);
    }
  };

  // Open confirmation modal for Escalate (P1)
  const openEscalateModal = () => {
    setDialogReason('');
    setConfirmDialog({
      type: 'escalate',
      title: 'Escalate Incident to P1 Priority',
      description:
        'This action elevates this threat to Critical Priority (P1) and records an immutable audit log entry. Are you sure you want to proceed?',
      requiresReason: true,
      reasonPlaceholder: 'Enter reason for escalation (e.g. lateral movement confirmed)...',
      confirmLabel: 'Escalate to P1',
      variant: 'destructive',
    });
  };

  // Open confirmation modal for Resolve
  const openResolveModal = () => {
    setConfirmDialog({
      type: 'resolve',
      title: 'Resolve Security Incident',
      description:
        'Mark this incident as resolved? This records your user ID as the resolving analyst along with a resolution timestamp.',
      requiresReason: false,
      confirmLabel: 'Mark as Resolved',
      variant: 'default',
    });
  };

  // Open confirmation modal for Reopen
  const openReopenModal = () => {
    setDialogReason('');
    setConfirmDialog({
      type: 'reopen',
      title: 'Reopen Security Incident',
      description:
        'Reopening this incident resets its state back to "open" and clears the resolution timestamp. Provide an optional reason.',
      requiresReason: true,
      reasonPlaceholder: 'Enter reason for reopening (e.g. recurring attack indicator)...',
      confirmLabel: 'Reopen Incident',
      variant: 'outline',
    });
  };

  // Execute confirmed workflow action
  const handleConfirmDialogAction = async () => {
    if (!confirmDialog || !activeIncident?.id) return;
    const { type } = confirmDialog;
    setActionLoading(type);
    setActionFeedback(null);

    try {
      if (type === 'escalate') {
        const updated = await incidentService.escalateIncident(
          activeIncident.id,
          dialogReason.trim() || 'Analyst escalation'
        );
        setActiveIncident((prev) => ({
          ...prev,
          priority: 'P1',
          escalated_at: updated?.escalated_at || new Date().toISOString(),
        }));
        setIncidents((prev) =>
          prev.map((i) => (i.id === activeIncident.id ? { ...i, priority: 'P1' } : i))
        );
        if (workspaceData?.incident) {
          setWorkspaceData((prev) => ({
            ...prev,
            incident: { ...prev.incident, priority: 'P1' },
          }));
        }
        setActionFeedback({ type: 'success', message: 'Incident escalated to P1 priority.' });
      } else if (type === 'resolve') {
        const updated = await incidentService.resolveIncident(activeIncident.id);
        setActiveIncident((prev) => ({
          ...prev,
          status: 'resolved',
          resolved_at: updated?.resolved_at || new Date().toISOString(),
          resolved_by: user?.id,
        }));
        setIncidents((prev) =>
          prev.map((i) => (i.id === activeIncident.id ? { ...i, status: 'resolved' } : i))
        );
        if (workspaceData?.incident) {
          setWorkspaceData((prev) => ({
            ...prev,
            incident: { ...prev.incident, status: 'resolved' },
          }));
        }
        setActionFeedback({ type: 'success', message: 'Incident marked as resolved.' });
      } else if (type === 'reopen') {
        const updated = await incidentService.reopenIncident(
          activeIncident.id,
          dialogReason.trim() || 'Analyst reopen'
        );
        setActiveIncident((prev) => ({
          ...prev,
          status: 'open',
          resolved_at: null,
          resolved_by: null,
        }));
        setIncidents((prev) =>
          prev.map((i) => (i.id === activeIncident.id ? { ...i, status: 'open' } : i))
        );
        if (workspaceData?.incident) {
          setWorkspaceData((prev) => ({
            ...prev,
            incident: { ...prev.incident, status: 'open' },
          }));
        }
        setActionFeedback({ type: 'success', message: 'Incident reopened to open status.' });
      }
      setTimeout(() => setActionFeedback(null), 3000);
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message: err.message || `Failed to ${type} incident`,
      });
    } finally {
      setActionLoading(null);
      setConfirmDialog(null);
    }
  };

  // Toggle Recommended Action status (PATCH /api/v1/actions/:id)
  const handleToggleActionStatus = async (actionId, targetStatus) => {
    try {
      await incidentService.updateActionStatus(actionId, targetStatus);
      // Update locally in drawer
      setActiveIncident((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          recommended_actions: prev.recommended_actions?.map((act) =>
            act.id === actionId ? { ...act, action_status: targetStatus } : act
          ),
        };
      });
    } catch (err) {
      // Local optimistic fallback
      setActiveIncident((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          recommended_actions: prev.recommended_actions?.map((act) =>
            act.id === actionId ? { ...act, action_status: targetStatus } : act
          ),
        };
      });
    }
  };

  // Update Incident Status (PATCH /api/v1/incidents/:id - Admin only)
  const handleUpdateIncidentStatus = async (newStatus) => {
    if (!activeIncident) return;
    try {
      await incidentService.updateIncidentStatus(activeIncident.id, newStatus);
      // Update local state in drawer and table list
      setActiveIncident((prev) => ({ ...prev, status: newStatus }));
      setIncidents((prev) =>
        prev.map((i) => (i.id === activeIncident.id ? { ...i, status: newStatus } : i))
      );
    } catch (err) {
      // Local optimistic fallback
      setActiveIncident((prev) => ({ ...prev, status: newStatus }));
      setIncidents((prev) =>
        prev.map((i) => (i.id === activeIncident.id ? { ...i, status: newStatus } : i))
      );
    }
  };

  const handleClearFilters = () => {
    setRiskFilter('all');
    setStatusFilter('all');
    setThreatFilter('all');
    setSearchQuery('');
    setOffset(0);
  };

  const hasActiveFilters =
    riskFilter !== 'all' ||
    statusFilter !== 'all' ||
    threatFilter !== 'all' ||
    searchQuery.trim() !== '';

  // Client-side text search within currently returned server page
  const displayIncidents = useMemo(() => {
    if (!searchQuery.trim()) return incidents;
    const q = searchQuery.toLowerCase().trim();
    return incidents.filter(
      (inc) =>
        (inc.explanation && inc.explanation.toLowerCase().includes(q)) ||
        (inc.id && inc.id.toLowerCase().includes(q)) ||
        (inc.threat_type && inc.threat_type.toLowerCase().includes(q)) ||
        (inc.source_type && inc.source_type.toLowerCase().includes(q))
    );
  }, [incidents, searchQuery]);

  const startItem = totalCount === 0 ? 0 : offset + 1;
  const endItem = Math.min(offset + limit, totalCount);

  const handleCopyId = (id) => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto w-full pb-12 font-sans">
      {/* 1. Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
            Incidents
          </h1>
          <p className="font-body text-xs text-muted-foreground mt-1">
            Review, investigate, and triage security threats logged across organization endpoints
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={fetchIncidents}
          isLoading={isLoading}
          className="h-8 px-2.5 text-xs font-mono self-start sm:self-auto"
        >
          <RefreshCw className={cn('w-3.5 h-3.5 mr-1.5', isLoading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* API Notice / Degradation Banner */}
      {apiError && (
        <div className="p-3.5 rounded-xl bg-muted/40 border border-border text-xs text-muted-foreground flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-500 shrink-0" />
            <span>Gateway Notice: {apiError}. Verify database status.</span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchIncidents}
            className="text-xs h-7 self-start sm:self-auto text-primary hover:underline"
          >
            Retry Query
          </Button>
        </div>
      )}

      {/* 2. Filter Bar (Server-side controls) */}
      <div className="p-4 rounded-xl bg-card border border-border flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 flex-1">
          {/* Risk Level Dropdown */}
          <Select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Risk Level"
          >
            <option value="all">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="safe">Safe</option>
          </Select>

          {/* Status Dropdown */}
          <Select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Status"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </Select>

          {/* Threat Type Dropdown */}
          <Select
            value={threatFilter}
            onChange={(e) => {
              setThreatFilter(e.target.value);
              setOffset(0);
            }}
            aria-label="Filter by Threat Type"
          >
            <option value="all">All Threat Types</option>
            {THREAT_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </Select>

          {/* Search Query Input */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 absolute left-3 text-muted-foreground pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search current page..."
              className="flex h-9 w-full rounded-lg border border-input bg-background pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-sans"
            />
          </div>
        </div>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleClearFilters}
            className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline font-medium shrink-0 self-start lg:self-center pt-1 lg:pt-0"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Clear filters</span>
          </button>
        )}
      </div>

      {/* 3. Incidents Table / Cards View */}
      <div ref={tableContainerRef} className="rounded-xl bg-card border border-border overflow-hidden">
        {isLoading ? (
          <div className="p-4 space-y-4">
            <div className="hidden md:block space-y-3">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-4 py-3 border-b border-border/50 animate-pulse">
                  <div className="w-20 h-6 bg-muted rounded"></div>
                  <div className="w-28 h-5 bg-muted rounded"></div>
                  <div className="w-16 h-5 bg-muted rounded"></div>
                  <div className="flex-1 h-5 bg-muted rounded"></div>
                  <div className="w-24 h-5 bg-muted rounded"></div>
                  <div className="w-20 h-5 bg-muted rounded"></div>
                </div>
              ))}
            </div>
            <div className="block md:hidden space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="p-4 rounded-lg bg-muted/30 border border-border space-y-3 animate-pulse">
                  <div className="flex justify-between">
                    <div className="w-20 h-5 bg-muted rounded"></div>
                    <div className="w-16 h-4 bg-muted rounded"></div>
                  </div>
                  <div className="w-40 h-4 bg-muted rounded"></div>
                  <div className="w-full h-8 bg-muted/60 rounded"></div>
                </div>
              ))}
            </div>
          </div>
        ) : displayIncidents.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={ShieldAlert}
              title="No incidents match your filters"
              description="Adjust your risk tier, status, or threat type criteria to inspect security records."
              actionLabel="Clear filters"
              onAction={handleClearFilters}
            />
          </div>
        ) : (
          <>
            {/* Desktop Table View */}
            <div className="hidden md:block overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/40 hover:bg-muted/40 text-[10px] font-mono uppercase tracking-wider text-muted-foreground border-b border-border">
                    <TableHead className="w-28">Risk</TableHead>
                    <TableHead className="w-40">Threat Type</TableHead>
                    <TableHead className="w-24">Source</TableHead>
                    <TableHead>Explanation</TableHead>
                    <TableHead className="w-32">Status</TableHead>
                    <TableHead className="w-32 text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayIncidents.map((incident) => (
                    <TableRow
                      key={incident.id}
                      data-incident-id={incident.id}
                      onClick={() => handleOpenIncident(incident)}
                      className="cursor-pointer hover:bg-muted/50 transition-colors group"
                    >
                      <TableCell className="py-3">
                        <RiskBadge level={normalizeRisk(incident.risk_level)} size="sm" />
                      </TableCell>
                      <TableCell className="font-medium text-xs text-foreground group-hover:text-primary transition-colors">
                        {formatThreatType(incident.threat_type)}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground uppercase">
                        {incident.source_type}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-md">
                        <span className="text-foreground font-normal" title={incident.explanation}>
                          {truncate(incident.explanation, 75)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            incident.status === 'resolved'
                              ? 'success'
                              : incident.status === 'investigating'
                              ? 'accent'
                              : 'warning'
                          }
                          size="sm"
                          className="capitalize"
                        >
                          {incident.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-muted-foreground">
                        {formatRelativeTime(incident.created_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {/* Mobile Stacked Cards View */}
            <div className="block md:hidden divide-y divide-border">
              {displayIncidents.map((incident) => (
                <div
                  key={incident.id}
                  data-incident-id={incident.id}
                  onClick={() => handleOpenIncident(incident)}
                  className="p-4 space-y-2.5 active:bg-muted/60 transition-colors cursor-pointer"
                >
                  <div className="flex items-center justify-between">
                    <RiskBadge level={normalizeRisk(incident.risk_level)} size="sm" />
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {formatRelativeTime(incident.created_at)}
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <span className="font-headline font-semibold text-xs text-foreground">
                      {formatThreatType(incident.threat_type)}
                    </span>
                    <span className="font-mono text-[10px] uppercase text-muted-foreground bg-muted/60 px-1.5 py-0.5 rounded">
                      {incident.source_type}
                    </span>
                  </div>

                  <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                    {incident.explanation}
                  </p>

                  <div className="flex items-center justify-between pt-1">
                    <Badge
                      variant={
                        incident.status === 'resolved'
                          ? 'success'
                          : incident.status === 'investigating'
                          ? 'accent'
                          : 'warning'
                      }
                      size="sm"
                      className="capitalize"
                    >
                      {incident.status}
                    </Badge>
                    <span className="text-[11px] text-primary font-medium inline-flex items-center gap-1">
                      Details →
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* 4. Pagination Footer (Server-side limit/offset) */}
        <div className="p-4 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-border bg-card">
          <span className="text-xs font-mono text-muted-foreground">
            Showing <strong className="text-foreground">{startItem}-{endItem}</strong> of{' '}
            <strong className="text-foreground">{totalCount}</strong> incidents
          </span>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="text-xs h-8 px-3"
            >
              <ChevronLeft className="w-3.5 h-3.5 mr-1" />
              Previous
            </Button>

            <Button
              variant="outline"
              size="sm"
              disabled={offset + limit >= totalCount}
              onClick={() => setOffset(offset + limit)}
              className="text-xs h-8 px-3"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </div>
        </div>
      </div>      {/* 5. Detail Drawer */}
      <Drawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        size="2xl"
        className="w-full sm:max-w-xl md:max-w-2xl lg:max-w-3xl xl:max-w-4xl"
      >
        {isDrawerLoading ? (
          <div className="space-y-6 animate-pulse p-2">
            <div className="space-y-2 pb-4 border-b border-border">
              <div className="w-24 h-6 bg-muted rounded"></div>
              <div className="w-48 h-6 bg-muted rounded"></div>
            </div>
            <div className="space-y-2">
              <div className="w-24 h-4 bg-muted rounded"></div>
              <div className="w-full h-16 bg-muted/60 rounded"></div>
            </div>
            <div className="space-y-2">
              <div className="w-32 h-4 bg-muted rounded"></div>
              <div className="w-full h-24 bg-muted/60 rounded"></div>
            </div>
          </div>
        ) : activeIncident ? (
          <div className="space-y-6 font-sans">
            {/* Header: Large RiskBadge + threat_type + source + calibrated score */}
            <div className="space-y-3 pb-4 border-b border-border">
              <div className="flex items-center justify-between gap-3">
                <RiskBadge level={normalizeRisk(activeIncident.risk_level)} size="lg" />
                <Badge
                  variant={
                    activeIncident.status === 'resolved'
                      ? 'success'
                      : activeIncident.status === 'investigating'
                      ? 'accent'
                      : 'warning'
                  }
                  size="sm"
                  className="capitalize font-mono"
                >
                  {activeIncident.status}
                </Badge>
              </div>

              <div>
                <h2 className="font-headline text-xl font-bold text-foreground">
                  {formatThreatType(activeIncident.threat_type)}
                </h2>
                <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-muted-foreground font-mono">
                  <span>Source: <strong className="text-foreground uppercase">{activeIncident.source_type}</strong></span>
                  {activeIncident.risk_score != null && (
                    <>
                      <span>•</span>
                      <span>Calibrated Score: <strong className="text-foreground">{activeIncident.risk_score}/100</strong></span>
                    </>
                  )}
                  {activeIncident.priority && (
                    <>
                      <span>•</span>
                      <span>Priority: <strong className={cn(activeIncident.priority === 'P1' ? 'text-destructive' : 'text-foreground')}>{activeIncident.priority}</strong></span>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* SOC Analyst Workflow Actions Bar */}
            <div className="p-3.5 rounded-xl bg-card border border-border space-y-2.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                    SOC Workflow
                  </span>
                  {activeIncident.priority && (
                    <span
                      className={cn(
                        'text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border',
                        activeIncident.priority === 'P1'
                          ? 'bg-destructive/15 text-destructive border-destructive/30'
                          : 'bg-muted text-muted-foreground border-border'
                      )}
                    >
                      {activeIncident.priority}
                    </span>
                  )}
                  {activeIncident.assigned_user_email && (
                    <span className="text-[11px] text-muted-foreground font-mono truncate max-w-[200px]">
                      Assigned: <strong className="text-foreground">{activeIncident.assigned_user_email}</strong>
                    </span>
                  )}
                </div>

                {/* Workflow Buttons */}
                <div className="flex flex-wrap items-center gap-1.5">
                  {/* Assign to Me */}
                  {user?.id && activeIncident.assigned_to !== user.id && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={actionLoading != null}
                      isLoading={actionLoading === 'assign'}
                      onClick={handleAssignToMe}
                      className="h-7 px-2.5 text-xs font-mono"
                    >
                      <UserCheck className="w-3.5 h-3.5 mr-1 text-primary" />
                      Assign to Me
                    </Button>
                  )}

                  {/* Escalate to P1 */}
                  {activeIncident.priority !== 'P1' && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={actionLoading != null}
                      onClick={openEscalateModal}
                      className="h-7 px-2.5 text-xs font-mono text-destructive hover:bg-destructive/10 border-destructive/30"
                    >
                      <Flame className="w-3.5 h-3.5 mr-1 text-destructive" />
                      Escalate (P1)
                    </Button>
                  )}

                  {/* Resolve (only if open or investigating) */}
                  {(activeIncident.status === 'open' || activeIncident.status === 'investigating') && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={actionLoading != null}
                      onClick={openResolveModal}
                      className="h-7 px-2.5 text-xs font-mono text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/10 border-emerald-500/30"
                    >
                      <CheckCircle className="w-3.5 h-3.5 mr-1 text-emerald-500" />
                      Resolve
                    </Button>
                  )}

                  {/* Reopen (only if resolved) */}
                  {activeIncident.status === 'resolved' && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={actionLoading != null}
                      onClick={openReopenModal}
                      className="h-7 px-2.5 text-xs font-mono text-amber-600 dark:text-amber-400 hover:bg-amber-500/10 border-amber-500/30"
                    >
                      <RotateCcw className="w-3.5 h-3.5 mr-1 text-amber-500" />
                      Reopen
                    </Button>
                  )}
                </div>
              </div>

              {/* Action feedback */}
              {actionFeedback && (
                <div
                  className={cn(
                    'text-xs px-2.5 py-1.5 rounded-lg border flex items-center justify-between',
                    actionFeedback.type === 'success'
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                      : 'bg-destructive/10 text-destructive border-destructive/30'
                  )}
                >
                  <span>{actionFeedback.message}</span>
                  <button
                    type="button"
                    onClick={() => setActionFeedback(null)}
                    className="text-[10px] font-mono hover:underline ml-2"
                  >
                    ✕
                  </button>
                </div>
              )}
            </div>

            {/* Drawer Tab Navigation */}
            <div className="flex items-center gap-1 p-1 bg-muted/50 rounded-xl border border-border shrink-0 overflow-x-auto">
              {[
                { id: 'overview', label: 'Overview', icon: Shield },
                {
                  id: 'investigation',
                  label: 'Investigation',
                  icon: FileText,
                  badge: workspaceData?.timeline?.length,
                },
                {
                  id: 'attack-chain',
                  label: 'Attack Chain',
                  icon: GitBranch,
                  badge: attackChainData?.chain_length,
                },
                {
                  id: 'related',
                  label: 'Related Incidents',
                  icon: Network,
                  badge: relatedData?.relationships?.length,
                },
              ].map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={isActive}
                    onClick={() => {
                      setActiveTab(tab.id);
                      if (tab.id === 'investigation' && !workspaceData && !isWorkspaceLoading) {
                        loadWorkspace(activeIncident.id);
                      } else if (tab.id === 'attack-chain' && !attackChainData && !isAttackChainLoading) {
                        loadAttackChain(activeIncident.id);
                      } else if (tab.id === 'related' && !relatedData && !isRelatedLoading) {
                        loadRelated(activeIncident.id);
                      }
                    }}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all shrink-0 font-sans',
                      isActive
                        ? 'bg-card text-foreground shadow-sm font-semibold border border-border/80'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/40'
                    )}
                  >
                    <Icon className={cn('w-3.5 h-3.5', isActive ? 'text-primary' : 'text-muted-foreground')} />
                    <span>{tab.label}</span>
                    {typeof tab.badge === 'number' && tab.badge > 0 && (
                      <span className="font-mono text-[10px] px-1.5 py-0.2 rounded-full bg-muted border border-border text-foreground font-semibold">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* TAB 1: OVERVIEW */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Explanation Section */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono">
                    Explanation
                  </h3>
                  <div className="p-3.5 rounded-lg bg-muted/30 border border-border">
                    <p className="text-xs text-foreground leading-relaxed">
                      {activeIncident.explanation}
                    </p>
                  </div>
                </div>

                {/* MITRE ATT&CK Section */}
                <div className="space-y-2">
                  <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono">
                    MITRE ATT&CK Mapping
                  </h3>
                  {activeIncident.mitre_mappings && activeIncident.mitre_mappings.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {activeIncident.mitre_mappings.map((m) => (
                        <div
                          key={m.technique_id || m.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-muted/60 border border-border text-xs font-mono"
                        >
                          <span className="text-primary font-bold">{m.technique_id}</span>
                          <span className="text-muted-foreground">•</span>
                          <span className="text-foreground">{m.technique_name}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">
                      No MITRE ATT&CK techniques mapped to this anomaly.
                    </p>
                  )}
                </div>

                {/* Recommended Actions Section */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono">
                      Recommended Actions
                    </h3>
                  </div>

                  <div className="space-y-2.5">
                    {activeIncident.recommended_actions && activeIncident.recommended_actions.length > 0 ? (
                      activeIncident.recommended_actions.map((rawAct, idx) => {
                        const act = normalizeAction(rawAct, idx);
                        return (
                          <div
                            key={act.id}
                            className={cn(
                              'p-3.5 rounded-lg border transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3',
                              act.action_status === 'taken'
                                ? 'bg-emerald-500/5 border-emerald-500/30'
                                : act.action_status === 'dismissed'
                                ? 'bg-muted/20 border-border opacity-70'
                                : 'bg-card border-border'
                            )}
                          >
                            <div className="space-y-1.5 flex-1">
                              <span className="text-xs font-medium text-foreground leading-snug">
                                {act.action_type}
                              </span>
                              <div>
                                <span
                                  className={cn(
                                    'inline-block font-mono text-[10px] px-2 py-0.5 rounded font-semibold uppercase',
                                    act.action_status === 'taken'
                                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                                      : act.action_status === 'dismissed'
                                      ? 'bg-muted text-muted-foreground border border-border'
                                      : 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                                  )}
                                >
                                  {act.action_status}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-center">
                              <Button
                                size="sm"
                                variant={act.action_status === 'taken' ? 'secondary' : 'outline'}
                                onClick={() => handleToggleActionStatus(act.id, 'taken')}
                                className="h-7 px-2.5 text-xs font-mono"
                              >
                                {act.action_status === 'taken' ? (
                                  <>
                                    <Check className="w-3 h-3 mr-1 text-emerald-500" />
                                    Taken
                                  </>
                                ) : (
                                  'Mark Taken'
                                )}
                              </Button>
                              <Button
                                size="sm"
                                variant={act.action_status === 'dismissed' ? 'secondary' : 'ghost'}
                                onClick={() => handleToggleActionStatus(act.id, 'dismissed')}
                                className="h-7 px-2.5 text-xs font-mono text-muted-foreground hover:text-foreground"
                              >
                                {act.action_status === 'dismissed' ? 'Dismissed' : 'Dismiss'}
                              </Button>
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      <p className="text-xs text-muted-foreground italic">
                        No recommended actions specified for this incident.
                      </p>
                    )}
                  </div>
                </div>

                {/* Admin Controls Section */}
                <div className="pt-5 border-t border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono">
                      Admin Controls
                    </span>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border uppercase font-semibold">
                      Admin Only
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Update triage state via PATCH /api/v1/incidents/:id.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {['open', 'investigating', 'resolved'].map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => handleUpdateIncidentStatus(s)}
                        className={cn(
                          'px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all border font-sans',
                          activeIncident.status === s
                            ? s === 'resolved'
                              ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/40 font-semibold shadow-sm'
                              : s === 'investigating'
                              ? 'bg-primary/15 text-primary border-primary/40 font-semibold shadow-sm'
                              : 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/40 font-semibold shadow-sm'
                            : 'bg-card text-muted-foreground border-border hover:text-foreground hover:bg-muted/40'
                        )}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Metadata Footer */}
                <div className="pt-5 border-t border-border space-y-2 text-xs font-mono text-muted-foreground">
                  <div className="flex items-center justify-between">
                    <span>Created At:</span>
                    <span className="text-foreground">{formatTimestamp(activeIncident.created_at)}</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span>Incident ID:</span>
                    <button
                      type="button"
                      onClick={() => handleCopyId(activeIncident.id)}
                      className="text-foreground hover:text-primary transition-colors flex items-center gap-1 select-all"
                      title="Click to copy UUID"
                    >
                      <span className="truncate max-w-[220px]">{activeIncident.id}</span>
                      {copiedId ? (
                        <Check className="w-3.5 h-3.5 text-emerald-500" />
                      ) : (
                        <Copy className="w-3.5 h-3.5 text-muted-foreground" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: INVESTIGATION WORKSPACE */}
            {activeTab === 'investigation' && (
              <div className="space-y-6">
                {isWorkspaceLoading ? (
                  <div className="space-y-4 animate-pulse p-2">
                    <div className="h-16 bg-muted/60 rounded-xl" />
                    <div className="h-32 bg-muted/60 rounded-xl" />
                    <div className="h-48 bg-muted/60 rounded-xl" />
                  </div>
                ) : workspaceError ? (
                  <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-xs text-destructive space-y-2">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{workspaceError}</span>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => loadWorkspace(activeIncident.id)}
                      className="text-xs h-7"
                    >
                      Retry Workspace Query
                    </Button>
                  </div>
                ) : (
                  <>
                    {/* Investigation Metadata Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                      <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-1">
                        <span className="text-[10px] font-mono uppercase text-muted-foreground">Priority Tier</span>
                        <div className="flex items-center gap-2">
                          <span className={cn('text-xs font-bold font-mono', activeIncident.priority === 'P1' ? 'text-destructive' : 'text-foreground')}>
                            {workspaceData?.incident?.priority || activeIncident.priority || 'P3'}
                          </span>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-1">
                        <span className="text-[10px] font-mono uppercase text-muted-foreground">Assignee</span>
                        <div className="text-xs font-mono text-foreground truncate">
                          {workspaceData?.incident?.assigned_user_email || activeIncident.assigned_user_email || 'Unassigned'}
                        </div>
                      </div>

                      {workspaceData?.incident?.device_name && (
                        <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-1">
                          <span className="text-[10px] font-mono uppercase text-muted-foreground">Device Host</span>
                          <div className="text-xs font-mono text-foreground truncate">
                            {workspaceData.incident.device_name} ({workspaceData.incident.device_platform || 'device'})
                          </div>
                        </div>
                      )}

                      {workspaceData?.group && (
                        <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-1 sm:col-span-2 md:col-span-3">
                          <span className="text-[10px] font-mono uppercase text-muted-foreground">Campaign Cluster</span>
                          <div className="text-xs font-semibold text-foreground flex items-center gap-2">
                            <Layers className="w-3.5 h-3.5 text-primary" />
                            <span>{workspaceData.group.title}</span>
                            <Badge variant="outline" size="sm" className="font-mono text-[9px] uppercase">
                              {workspaceData.group.group_type}
                            </Badge>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Append-Only Analyst Notes Section */}
                    <div className="space-y-3 pt-2">
                      <div className="flex items-center justify-between">
                        <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                          <FileText className="w-3.5 h-3.5 text-primary" />
                          <span>Analyst Notes ({workspaceData?.notes?.length || 0})</span>
                        </h3>
                        <span className="text-[10px] font-mono text-muted-foreground">Append-Only Audit</span>
                      </div>

                      {/* Notes List */}
                      <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                        {workspaceData?.notes && workspaceData.notes.length > 0 ? (
                          workspaceData.notes.map((n) => (
                            <div key={n.id} className="p-3 rounded-lg bg-muted/30 border border-border space-y-1 text-xs">
                              <div className="flex items-center justify-between text-[11px] font-mono text-muted-foreground pb-1 border-b border-border/40">
                                <span className="text-foreground font-semibold">
                                  {n.author_email || n.author_name || 'Analyst'}
                                  {n.author_role && ` (${n.author_role})`}
                                </span>
                                <span>{formatRelativeTime(n.created_at)}</span>
                              </div>
                              <p className="text-xs text-foreground whitespace-pre-wrap leading-relaxed pt-1">
                                {n.note}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div className="p-4 rounded-lg bg-muted/20 border border-border text-center text-xs text-muted-foreground italic">
                            No investigation notes yet. Add the first observation below.
                          </div>
                        )}
                      </div>

                      {/* Append Note Composer */}
                      <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-border/60">
                        <textarea
                          rows={2}
                          value={newNoteText}
                          onChange={(e) => setNewNoteText(e.target.value)}
                          placeholder="Add investigation observation or analyst rationale (append-only)..."
                          className="w-full rounded-lg border border-input bg-background p-2.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-sans resize-none"
                        />
                        <div className="flex items-center justify-between gap-2">
                          {noteFeedback && (
                            <span
                              className={cn(
                                'text-[11px] font-mono',
                                noteFeedback.type === 'success' ? 'text-emerald-500' : 'text-destructive'
                              )}
                            >
                              {noteFeedback.message}
                            </span>
                          )}
                          <div className="ml-auto">
                            <Button
                              type="submit"
                              size="sm"
                              isLoading={isSubmittingNote}
                              disabled={!newNoteText.trim() || isSubmittingNote}
                              className="text-xs h-7 px-3 font-mono"
                            >
                              <Send className="w-3 h-3 mr-1" />
                              Record Note
                            </Button>
                          </div>
                        </div>
                      </form>
                    </div>

                    {/* Unified Chronological Timeline */}
                    <div className="space-y-3 pt-3 border-t border-border">
                      <div className="flex items-center justify-between">
                        <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-primary" />
                          <span>Investigation Timeline ({workspaceData?.timeline?.length || 0})</span>
                        </h3>
                        <span className="text-[10px] font-mono text-muted-foreground">Chronological Ascending</span>
                      </div>

                      <div className="space-y-2.5">
                        {workspaceData?.timeline && workspaceData.timeline.length > 0 ? (
                          workspaceData.timeline.map((ev) => {
                            const badge = getTimelineBadge(ev.event_type);
                            const EvIcon = badge.icon;
                            return (
                              <div
                                key={ev.id}
                                className="p-3 rounded-lg bg-card border border-border flex items-start gap-3 transition-colors hover:bg-muted/30 text-xs"
                              >
                                <div className={cn('p-1.5 rounded-md border shrink-0 mt-0.5', badge.color)}>
                                  <EvIcon className="w-3.5 h-3.5" />
                                </div>
                                <div className="flex-1 space-y-1 min-w-0">
                                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                                    <span className="font-semibold text-foreground text-xs">{ev.title}</span>
                                    <span className="font-mono text-[10px] text-muted-foreground shrink-0">
                                      {formatTimestamp(ev.timestamp)}
                                    </span>
                                  </div>
                                  <p className="text-xs text-muted-foreground leading-relaxed break-words">
                                    {ev.description}
                                  </p>
                                </div>
                              </div>
                            );
                          })
                        ) : (
                          <div className="p-4 rounded-lg bg-muted/20 border border-border text-center text-xs text-muted-foreground italic">
                            No timeline events recorded for this incident.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Detection Signals (if present) */}
                    {workspaceData?.signals && workspaceData.signals.length > 0 && (
                      <div className="space-y-2 pt-3 border-t border-border">
                        <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                          <Activity className="w-3.5 h-3.5 text-sky-500" />
                          <span>Detection Signals ({workspaceData.signals.length})</span>
                        </h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {workspaceData.signals.map((sig) => (
                            <div key={sig.id} className="p-2.5 rounded-lg bg-muted/30 border border-border text-xs space-y-1">
                              <div className="flex items-center justify-between font-mono text-[11px]">
                                <span className="font-semibold text-foreground">{sig.signal_name}</span>
                                <span className="text-muted-foreground">weight: {sig.weight}</span>
                              </div>
                              <div className="text-muted-foreground font-mono text-[11px] truncate">
                                value: {sig.signal_value}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Threat Intel IOC Matches (if present) */}
                    {workspaceData?.iocs && workspaceData.iocs.length > 0 && (
                      <div className="space-y-2 pt-3 border-t border-border">
                        <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                          <Crosshair className="w-3.5 h-3.5 text-amber-500" />
                          <span>Threat Intel IOC Matches ({workspaceData.iocs.length})</span>
                        </h3>
                        <div className="space-y-1.5">
                          {workspaceData.iocs.map((ioc) => (
                            <div key={ioc.id} className="p-2.5 rounded-lg bg-muted/30 border border-border text-xs flex items-center justify-between gap-2">
                              <span className="font-mono text-foreground font-semibold truncate">{ioc.matched_value}</span>
                              <div className="flex items-center gap-2 shrink-0 font-mono text-[10px]">
                                <span className="uppercase text-amber-500">{ioc.severity || 'high'}</span>
                                <span className="text-muted-foreground">• {ioc.feed_source}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* TAB 3: ATTACK CHAIN */}
            {activeTab === 'attack-chain' && (
              <div className="space-y-6">
                {isAttackChainLoading ? (
                  <div className="space-y-4 animate-pulse p-2">
                    <div className="h-16 bg-muted/60 rounded-xl" />
                    <div className="h-40 bg-muted/60 rounded-xl" />
                    <div className="h-48 bg-muted/60 rounded-xl" />
                  </div>
                ) : attackChainError ? (
                  <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-xs text-destructive space-y-2">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{attackChainError}</span>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => loadAttackChain(activeIncident.id)}
                      className="text-xs h-7"
                    >
                      Retry Attack Chain Query
                    </Button>
                  </div>
                ) : !attackChainData || !attackChainData.timeline || attackChainData.timeline.length === 0 ? (
                  <div className="p-8">
                    <EmptyState
                      icon={GitBranch}
                      title="No attack-chain activity available"
                      description="Attack chain progression requires multi-stage correlated MITRE techniques (Initial Access → Execution → Privilege Escalation → C2)."
                    />
                  </div>
                ) : (
                  <>
                    {/* Chain Metrics Summary */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <div className="p-3.5 rounded-xl bg-card border border-border space-y-1">
                        <span className="text-[10px] font-mono uppercase text-muted-foreground">Chain Stages</span>
                        <div className="font-headline text-lg font-bold text-foreground">
                          {attackChainData.chain_length}
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-card border border-border space-y-1">
                        <span className="text-[10px] font-mono uppercase text-muted-foreground">Progression Confidence</span>
                        <div className="font-headline text-lg font-bold text-primary">
                          {Math.round((attackChainData.confidence_score || 0.8) * 100)}%
                        </div>
                      </div>

                      <div className="p-3.5 rounded-xl bg-card border border-border space-y-1 col-span-2 sm:col-span-1">
                        <span className="text-[10px] font-mono uppercase text-muted-foreground">Root Incident</span>
                        <div className="text-xs font-mono text-foreground truncate">
                          {attackChainData.root_incident?.id === activeIncident.id ? 'This Incident' : attackChainData.root_incident?.threat_type || 'Initiator'}
                        </div>
                      </div>
                    </div>

                    {/* Progression Timeline */}
                    <div className="space-y-3">
                      <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                        <GitBranch className="w-3.5 h-3.5 text-primary" />
                        <span>Progression Timeline ({attackChainData.timeline.length} Stages)</span>
                      </h3>

                      <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-border/60">
                        {attackChainData.timeline.map((step, idx) => {
                          const isCurrent = step.incident_id === activeIncident.id;
                          return (
                            <div key={step.incident_id || idx} className="relative pl-8 space-y-1 text-xs">
                              {/* Step circle indicator */}
                              <div
                                className={cn(
                                  'absolute left-2 top-2 w-3.5 h-3.5 rounded-full border-2 bg-background -translate-x-1/2',
                                  isCurrent ? 'border-primary ring-2 ring-primary/20 bg-primary' : 'border-muted-foreground'
                                )}
                              />

                              <div className={cn('p-3.5 rounded-xl border transition-colors space-y-2', isCurrent ? 'bg-primary/5 border-primary/40' : 'bg-card border-border')}>
                                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                                  <div className="flex items-center gap-2">
                                    <span className="font-bold text-foreground text-xs">
                                      Stage {idx + 1}: {formatThreatType(step.threat_type)}
                                    </span>
                                    {isCurrent && (
                                      <Badge variant="primary" size="sm" className="font-mono text-[9px] uppercase">
                                        Current
                                      </Badge>
                                    )}
                                  </div>
                                  <span className="font-mono text-[10px] text-muted-foreground">
                                    {formatRelativeTime(step.created_at)}
                                  </span>
                                </div>

                                {/* Step details */}
                                <div className="flex flex-wrap items-center gap-2 pt-1">
                                  {step.mitre_tactics && step.mitre_tactics.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5">
                                      {step.mitre_tactics.map((tac) => (
                                        <span
                                          key={tac}
                                          className="font-mono text-[10px] px-2 py-0.5 rounded bg-primary/15 text-primary border border-primary/30 font-semibold"
                                        >
                                          {tac}: {MITRE_TACTIC_NAMES[tac] || tac}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                  {step.relationship && (
                                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                                      via {step.relationship.replace(/_/g, ' ')}
                                    </span>
                                  )}
                                </div>

                                {!isCurrent && step.incident_id && (
                                  <div className="pt-1">
                                    <button
                                      type="button"
                                      onClick={() => handleOpenIncidentById(step.incident_id)}
                                      className="text-primary text-xs font-mono hover:underline inline-flex items-center gap-1"
                                    >
                                      Inspect Stage Incident →
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Attack Chain Graph Representation */}
                    {attackChainGraph?.nodes && attackChainGraph.nodes.length > 0 && (
                      <div className="space-y-3 pt-4 border-t border-border">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                            <Network className="w-3.5 h-3.5 text-primary" />
                            <span>Progression Graph Topology</span>
                          </h3>
                          <span className="text-[10px] font-mono text-muted-foreground">
                            {attackChainGraph.nodes.length} Nodes • {attackChainGraph.edges?.length || 0} Transitions
                          </span>
                        </div>

                        {/* Interactive Topology Cards */}
                        <div className="p-4 rounded-xl bg-muted/20 border border-border space-y-3 overflow-x-auto">
                          <div className="flex flex-wrap items-center justify-center gap-4 py-2">
                            {attackChainGraph.nodes.map((node, nIdx) => {
                              const isNodeActive = node.id === activeIncident.id;
                              return (
                                <React.Fragment key={node.id}>
                                  <div
                                    className={cn(
                                      'p-3 rounded-xl border text-center transition-all min-w-[140px] space-y-1',
                                      isNodeActive
                                        ? 'bg-primary/10 border-primary ring-2 ring-primary/20 shadow-sm'
                                        : 'bg-card border-border hover:border-primary/50'
                                    )}
                                  >
                                    <span className="block font-semibold text-xs text-foreground">
                                      {formatThreatType(node.label)}
                                    </span>
                                    <span className="block font-mono text-[9px] text-muted-foreground truncate max-w-[120px] mx-auto">
                                      {node.id}
                                    </span>
                                    {!isNodeActive && (
                                      <button
                                        type="button"
                                        onClick={() => handleOpenIncidentById(node.id)}
                                        className="text-[10px] text-primary hover:underline font-mono inline-block pt-1"
                                      >
                                        Inspect
                                      </button>
                                    )}
                                  </div>

                                  {nIdx < attackChainGraph.nodes.length - 1 && (
                                    <div className="flex flex-col items-center justify-center text-muted-foreground">
                                      <ArrowRight className="w-4 h-4 text-primary" />
                                      {attackChainGraph.edges?.[nIdx]?.type && (
                                        <span className="font-mono text-[9px] uppercase tracking-wide text-muted-foreground">
                                          {attackChainGraph.edges[nIdx].type.replace(/_/g, ' ')}
                                        </span>
                                      )}
                                    </div>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* TAB 4: RELATED INCIDENTS */}
            {activeTab === 'related' && (
              <div className="space-y-6">
                {isRelatedLoading ? (
                  <div className="space-y-3 animate-pulse p-2">
                    <div className="h-20 bg-muted/60 rounded-xl" />
                    <div className="h-20 bg-muted/60 rounded-xl" />
                  </div>
                ) : relatedError ? (
                  <div className="p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-xs text-destructive space-y-2">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>{relatedError}</span>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => loadRelated(activeIncident.id)}
                      className="text-xs h-7"
                    >
                      Retry Query
                    </Button>
                  </div>
                ) : !relatedData?.relationships || relatedData.relationships.length === 0 ? (
                  <div className="p-8">
                    <EmptyState
                      icon={Network}
                      title="No related incidents found"
                      description="No cross-incident correlations or shared entity relationships detected for this record."
                    />
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider font-mono flex items-center gap-1.5">
                        <Network className="w-3.5 h-3.5 text-primary" />
                        <span>Correlated Incidents ({relatedData.relationships.length})</span>
                      </h3>
                      <span className="text-[10px] font-mono text-muted-foreground">Graph Edges</span>
                    </div>

                    <div className="space-y-2.5">
                      {relatedData.relationships.map((rel, rIdx) => (
                        <div
                          key={rel.related_incident_id || rIdx}
                          className="p-3.5 rounded-xl bg-card border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs hover:border-border/80 transition-colors"
                        >
                          <div className="space-y-1.5 flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" size="sm" className="font-mono text-[10px] uppercase font-semibold">
                                {rel.relationship_type?.replace(/_/g, ' ') || 'Correlated'}
                              </Badge>
                              {rel.confidence_score != null && (
                                <span className="font-mono text-[10px] text-muted-foreground">
                                  Confidence: <strong className="text-foreground">{Math.round(rel.confidence_score * 100)}%</strong>
                                </span>
                              )}
                            </div>

                            <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                              <span>Target ID:</span>
                              <span className="text-foreground truncate max-w-[220px]">{rel.related_incident_id}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                            <span className="font-mono text-[10px] text-muted-foreground hidden md:inline">
                              {formatRelativeTime(rel.created_at)}
                            </span>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleOpenIncidentById(rel.related_incident_id)}
                              className="text-xs h-7 px-2.5 font-mono"
                            >
                              Inspect Incident →
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : null}
      </Drawer>

      {/* Confirmation Dialog for SOC Workflow Actions */}
      <Dialog open={!!confirmDialog} onOpenChange={(open) => !open && setConfirmDialog(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{confirmDialog?.title}</DialogTitle>
            <DialogDescription>{confirmDialog?.description}</DialogDescription>
          </DialogHeader>

          {confirmDialog?.requiresReason && (
            <div className="space-y-1.5 py-2">
              <label className="text-xs font-mono text-muted-foreground">Reason (Optional)</label>
              <input
                type="text"
                value={dialogReason}
                onChange={(e) => setDialogReason(e.target.value)}
                placeholder={confirmDialog.reasonPlaceholder || 'Enter reason...'}
                className="w-full h-9 rounded-lg border border-input bg-background px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary font-sans"
              />
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="ghost"
              size="sm"
              disabled={actionLoading != null}
              onClick={() => setConfirmDialog(null)}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              variant={confirmDialog?.variant === 'destructive' ? 'destructive' : 'default'}
              size="sm"
              isLoading={actionLoading != null}
              disabled={actionLoading != null}
              onClick={handleConfirmDialogAction}
              className="text-xs"
            >
              {confirmDialog?.confirmLabel || 'Confirm'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
