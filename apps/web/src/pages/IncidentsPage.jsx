import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { useSocket } from '../hooks/useSocket';
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

function formatThreatType(threatType) {
  const match = THREAT_TYPES.find((t) => t.value === threatType);
  if (match) return match.label;
  return threatType ? threatType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Unknown';
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

  // Detail Drawer state
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [activeIncident, setActiveIncident] = useState(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [isDrawerLoading, setIsDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState(null);
  const [copiedId, setCopiedId] = useState(false);

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

  // Fetch single incident details for detail drawer
  const handleOpenIncident = async (incident) => {
    setSelectedIncidentId(incident.id);
    setIsDrawerOpen(true);
    setIsDrawerLoading(true);
    setDrawerError(null);

    try {
      const data = await incidentService.getIncident(incident.id);
      setActiveIncident(data);
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
      </div>

      {/* 5. Detail Drawer */}
      <Drawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        size="xl"
        className="w-full sm:max-w-xl md:max-w-2xl"
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
          <div className="space-y-6">
            {/* Header: Large RiskBadge + threat_type */}
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
                <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground font-mono">
                  <span>Source: <strong className="text-foreground uppercase">{activeIncident.source_type}</strong></span>
                  {activeIncident.risk_score != null && (
                    <>
                      <span>•</span>
                      <span>Calibrated Score: <strong className="text-foreground">{activeIncident.risk_score}/100</strong></span>
                    </>
                  )}
                </div>
              </div>
            </div>

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
        ) : null}
      </Drawer>
    </div>
  );
}
