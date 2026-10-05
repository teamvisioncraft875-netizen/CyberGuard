import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { cn } from '../utils/cn';
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
  Input,
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../components/ui';
import { attackSurfaceService } from '../services';
import {
  Crosshair,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Server,
  Layers,
  Search,
  Filter,
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  Clock,
  Activity,
  Cpu,
  Lock,
  Radio,
  FileText,
  AlertOctagon,
  ArrowUpRight,
  BarChart3,
  TrendingUp,
  SlidersHorizontal,
} from 'lucide-react';

const SEVERITY_COLORS = {
  critical: 'text-rose-500 bg-rose-500/10 border-rose-500/30',
  high: 'text-amber-500 bg-amber-500/10 border-amber-500/30',
  medium: 'text-sky-500 bg-sky-500/10 border-sky-500/30',
  low: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/30',
  info: 'text-slate-400 bg-slate-400/10 border-slate-400/30',
};

const ACTION_ICONS = {
  notify_admin: Radio,
  block_port: Lock,
  restrict_firewall: ShieldAlert,
  isolate_device: Cpu,
};

export function AttackSurfacePage({ initialTab = 'overview', onTriggerToast }) {
  // Active top-level Tab: 'overview' | 'inventory' | 'analytics' | 'scans' | 'response-actions'
  const [activeTab, setActiveTab] = useState(initialTab);

  // Global loading and error states
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState(null);

  // Dashboard Data State
  const [dashboardData, setDashboardData] = useState(null);

  // Inventory Table State
  const [exposures, setExposures] = useState([]);
  const [inventoryTotal, setInventoryTotal] = useState(0);
  const [inventoryLimit, setInventoryLimit] = useState(25);
  const [inventoryOffset, setInventoryOffset] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('active');

  // Selected Exposure for Drawer Inspection
  const [selectedExposureId, setSelectedExposureId] = useState(null);
  const [exposureDetail, setExposureDetail] = useState(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);

  // Response Actions State
  const [actions, setActions] = useState([]);
  const [actionsTotal, setActionsTotal] = useState(0);
  const [selectedActionForApproval, setSelectedActionForApproval] = useState(null);
  const [approvalDecision, setApprovalDecision] = useState('approve'); // 'approve' | 'reject'
  const [approvalReason, setApprovalReason] = useState('');
  const [isSubmittingApproval, setIsSubmittingApproval] = useState(false);

  // Fleet Scans State
  const [scans, setScans] = useState([]);
  const [scansTotal, setScansTotal] = useState(0);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [scanTargetScope, setScanTargetScope] = useState('all');
  const [scanDeviceId, setScanDeviceId] = useState('');
  const [isTriggeringScan, setIsTriggeringScan] = useState(false);

  // Analytics State
  const [analyticsDays, setAnalyticsDays] = useState(14);
  const [analyticsData, setAnalyticsData] = useState(null);

  // Incident Inline Triage State (inside Drawer)
  const [incidentTriageStatus, setIncidentTriageStatus] = useState('');
  const [incidentTriageNote, setIncidentTriageNote] = useState('');
  const [isUpdatingIncident, setIsUpdatingIncident] = useState(false);

  // ───────────────────────────────────────────────────────────────────────────
  // Data Loaders
  // ───────────────────────────────────────────────────────────────────────────

  const fetchDashboard = useCallback(async () => {
    try {
      const data = await attackSurfaceService.getDashboard();
      setDashboardData(data);
    } catch (err) {
      console.error('[AttackSurface] Failed to load dashboard:', err);
      setErrorMsg(err.message || 'Failed to load Attack Surface Dashboard');
    }
  }, []);

  const fetchInventory = useCallback(async () => {
    try {
      const data = await attackSurfaceService.getExposures({
        status: filterStatus,
        severity: filterSeverity,
        search: searchQuery.trim() || undefined,
        limit: inventoryLimit,
        offset: inventoryOffset,
      });
      setExposures(data.exposures || []);
      setInventoryTotal(data.total || 0);
    } catch (err) {
      console.error('[AttackSurface] Failed to load inventory:', err);
    }
  }, [filterStatus, filterSeverity, searchQuery, inventoryLimit, inventoryOffset]);

  const fetchAnalytics = useCallback(async () => {
    try {
      const data = await attackSurfaceService.getAnalytics(analyticsDays);
      setAnalyticsData(data);
    } catch (err) {
      console.error('[AttackSurface] Failed to load analytics:', err);
    }
  }, [analyticsDays]);

  const fetchScans = useCallback(async () => {
    try {
      const data = await attackSurfaceService.getScans({ limit: 25, offset: 0 });
      setScans(data.scans || []);
      setScansTotal(data.total || 0);
    } catch (err) {
      console.error('[AttackSurface] Failed to load scan history:', err);
    }
  }, []);

  const fetchResponseActions = useCallback(async () => {
    try {
      const data = await attackSurfaceService.listResponseActions({ limit: 50, offset: 0 });
      setActions(data.actions || []);
      setActionsTotal(data.total || 0);
    } catch (err) {
      console.error('[AttackSurface] Failed to load response actions:', err);
    }
  }, []);

  // Initial Load & Tab switching
  useEffect(() => {
    setIsLoading(true);
    Promise.all([
      fetchDashboard(),
      fetchInventory(),
      fetchAnalytics(),
      fetchScans(),
      fetchResponseActions(),
    ]).finally(() => setIsLoading(false));
  }, [fetchDashboard, fetchInventory, fetchAnalytics, fetchScans, fetchResponseActions]);

  // Load single exposure details when Drawer opens
  useEffect(() => {
    if (!selectedExposureId) {
      setExposureDetail(null);
      return;
    }

    setIsDetailLoading(true);
    attackSurfaceService
      .getExposureById(selectedExposureId)
      .then((data) => {
        setExposureDetail(data);
        if (data?.incident) {
          setIncidentTriageStatus(data.incident.status || 'open');
        }
      })
      .catch((err) => {
        console.error('[AttackSurface] Failed to load exposure detail:', err);
        onTriggerToast?.('Failed to load exposure details: ' + err.message, 'error');
      })
      .finally(() => setIsDetailLoading(false));
  }, [selectedExposureId, onTriggerToast]);

  // Handle Response Action Approval / Rejection
  const handleSubmitActionDecision = async () => {
    if (!selectedActionForApproval) return;
    setIsSubmittingApproval(true);
    try {
      await attackSurfaceService.updateResponseAction(selectedActionForApproval.id, {
        action: approvalDecision,
        reason: approvalReason.trim() || undefined,
      });

      onTriggerToast?.(
        `Action ${selectedActionForApproval.action_type} successfully ${approvalDecision === 'approve' ? 'approved' : 'rejected'}.`,
        'success'
      );
      setSelectedActionForApproval(null);
      setApprovalReason('');
      fetchResponseActions();
      fetchDashboard();
    } catch (err) {
      console.error('[AttackSurface] Action decision error:', err);
      onTriggerToast?.('Error updating response action: ' + (err.response?.data?.message || err.message), 'error');
    } finally {
      setIsSubmittingApproval(false);
    }
  };

  // Handle Trigger Scan
  const handleTriggerScanSubmit = async (e) => {
    e.preventDefault();
    setIsTriggeringScan(true);
    try {
      const payload = {
        target_scope: scanTargetScope,
        device_id: scanTargetScope === 'device' ? scanDeviceId.trim() : undefined,
      };

      const res = await attackSurfaceService.triggerScan(payload);
      onTriggerToast?.(
        `Fleet scan initiated: ${res.queued_count || 1} agent command(s) queued.`,
        'success'
      );
      setIsScanModalOpen(false);
      setScanDeviceId('');
      fetchScans();
    } catch (err) {
      console.error('[AttackSurface] Scan trigger failed:', err);
      onTriggerToast?.('Failed to trigger fleet scan: ' + (err.response?.data?.message || err.message), 'error');
    } finally {
      setIsTriggeringScan(false);
    }
  };

  // Handle Inline Incident Update from Drawer
  const handleUpdateIncident = async () => {
    if (!exposureDetail?.incident_id) return;
    setIsUpdatingIncident(true);
    try {
      await attackSurfaceService.updateIncident(exposureDetail.incident_id, {
        status: incidentTriageStatus,
        note: incidentTriageNote.trim() || undefined,
      });

      onTriggerToast?.('Incident status & note updated successfully.', 'success');
      setIncidentTriageNote('');
      // Reload exposure detail and dashboard
      const updated = await attackSurfaceService.getExposureById(selectedExposureId);
      setExposureDetail(updated);
      fetchDashboard();
      fetchInventory();
    } catch (err) {
      console.error('[AttackSurface] Incident update failed:', err);
      onTriggerToast?.('Failed to update incident: ' + err.message, 'error');
    } finally {
      setIsUpdatingIncident(false);
    }
  };

  // ───────────────────────────────────────────────────────────────────────────
  // Render Tab Content
  // ───────────────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6 pb-12 font-sans selection:bg-primary selection:text-primary-foreground">
      {/* 1. Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/60 pb-5">
        <div>
          <div className="flex items-center gap-2.5 mb-1.5">
            <span className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Crosshair className="w-5 h-5 animate-pulse" />
            </span>
            <h1 className="text-2xl font-headline font-bold tracking-tight text-foreground">
              Attack Surface Discovery & Posture
            </h1>
            <Badge variant="outline" className="font-mono text-xs text-primary border-primary/30 uppercase">
              Phase C SOC
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Continuous listening port discovery, real-time exposure risk scoring, and shadow-mode automated policy response.
          </p>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setIsLoading(true);
              Promise.all([
                fetchDashboard(),
                fetchInventory(),
                fetchAnalytics(),
                fetchScans(),
                fetchResponseActions(),
              ]).finally(() => setIsLoading(false));
            }}
            disabled={isLoading}
            className="gap-2"
          >
            <RefreshCw className={cn('w-4 h-4', isLoading && 'animate-spin')} />
            Refresh
          </Button>

          <Button
            size="sm"
            onClick={() => setIsScanModalOpen(true)}
            className="gap-2 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold shadow-md"
          >
            <Play className="w-4 h-4 fill-current" />
            Scan Fleet
          </Button>
        </div>
      </div>

      {/* 2. Primary Navigation Tabs */}
      <div className="flex items-center border-b border-border/80 gap-1 overflow-x-auto">
        {[
          { id: 'overview', label: 'SOC Overview', icon: BarChart3 },
          { id: 'inventory', label: 'Exposure Inventory', icon: Layers, badge: dashboardData?.summary?.total_active },
          { id: 'analytics', label: 'Exposure Analytics', icon: TrendingUp },
          { id: 'scans', label: 'Fleet Scans', icon: Activity, badge: scansTotal },
          { id: 'response-actions', label: 'Response Actions', icon: Lock, badge: actions.filter((a) => a.status === 'proposed').length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition-all duration-150 select-none whitespace-nowrap',
                isActive
                  ? 'border-primary text-primary bg-primary/5'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
              )}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.badge !== undefined && tab.badge > 0 && (
                <span
                  className={cn(
                    'font-mono text-[10px] px-1.5 py-0.2 rounded-full font-bold',
                    isActive ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
                  )}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ───────────────────────────────────────────────────────────────────────
          TAB 1: SOC OVERVIEW DASHBOARD
      ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
            {[
              {
                label: 'Active Exposures',
                val: dashboardData?.summary?.total_active ?? 0,
                desc: 'Unmitigated entrypoints',
                icon: AlertTriangle,
                color: 'text-amber-500',
                border: 'border-amber-500/20',
              },
              {
                label: 'Critical Exposures',
                val: dashboardData?.summary?.critical_active ?? 0,
                desc: 'Risk score ≥ 90',
                icon: ShieldAlert,
                color: 'text-rose-500',
                border: 'border-rose-500/30 bg-rose-500/5',
              },
              {
                label: 'High Exposures',
                val: dashboardData?.summary?.high_active ?? 0,
                desc: 'Risk score 70 - 89',
                icon: AlertOctagon,
                color: 'text-orange-500',
                border: 'border-orange-500/20',
              },
              {
                label: 'Mitigated Exposures',
                val: dashboardData?.summary?.mitigated_total ?? 0,
                desc: 'Closed or filtered',
                icon: ShieldCheck,
                color: 'text-emerald-500',
                border: 'border-emerald-500/20',
              },
              {
                label: 'Impacted Devices',
                val: dashboardData?.summary?.devices_with_exposures ?? 0,
                desc: 'With open findings',
                icon: Server,
                color: 'text-sky-500',
                border: 'border-sky-500/20',
              },
              {
                label: 'Open Incidents',
                val: dashboardData?.summary?.open_incidents ?? 0,
                desc: 'Correlated in SOC',
                icon: Crosshair,
                color: 'text-purple-500',
                border: 'border-purple-500/20',
              },
            ].map((card, idx) => {
              const Icon = card.icon;
              return (
                <Card key={idx} className={cn('p-4 border shadow-sm relative overflow-hidden', card.border)}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider font-mono">
                      {card.label}
                    </span>
                    <Icon className={cn('w-4 h-4', card.color)} />
                  </div>
                  <div className={cn('text-2xl font-bold font-mono', card.color)}>{card.val}</div>
                  <div className="text-[11px] text-muted-foreground mt-1 truncate">{card.desc}</div>
                </Card>
              );
            })}
          </div>

          {/* Middle Row: Risk Distribution & Exposure Categories */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Risk Distribution Breakdown */}
            <Card className="p-5 border border-border/80">
              <div className="flex items-center justify-between pb-3 border-b border-border/60 mb-4">
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold font-headline">Risk Score Distribution</h3>
                </div>
                <span className="text-xs text-muted-foreground font-mono">Aggregated Findings</span>
              </div>

              <div className="space-y-4">
                {[
                  {
                    level: 'Critical (≥90)',
                    count: dashboardData?.risk_distribution?.critical || 0,
                    color: 'bg-rose-500',
                    textColor: 'text-rose-500',
                  },
                  {
                    level: 'High (70-89)',
                    count: dashboardData?.risk_distribution?.high || 0,
                    color: 'bg-amber-500',
                    textColor: 'text-amber-500',
                  },
                  {
                    level: 'Medium (40-69)',
                    count: dashboardData?.risk_distribution?.medium || 0,
                    color: 'bg-sky-500',
                    textColor: 'text-sky-500',
                  },
                  {
                    level: 'Low (1-39)',
                    count: dashboardData?.risk_distribution?.low || 0,
                    color: 'bg-emerald-500',
                    textColor: 'text-emerald-500',
                  },
                ].map((item, i) => {
                  const total = dashboardData?.summary?.total_active || 1;
                  const pct = Math.round((item.count / (total === 0 ? 1 : total)) * 100);
                  return (
                    <div key={i} className="space-y-1.5">
                      <div className="flex justify-between text-xs font-mono font-medium">
                        <span className={item.textColor}>{item.level}</span>
                        <span className="text-foreground">
                          {item.count} <span className="text-muted-foreground text-[10px]">({pct}%)</span>
                        </span>
                      </div>
                      <div className="h-2 w-full bg-muted/60 rounded-full overflow-hidden">
                        <div
                          className={cn('h-full transition-all duration-500 rounded-full', item.color)}
                          style={{ width: `${Math.max(pct, item.count > 0 ? 4 : 0)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>

            {/* Exposure Categories Breakdown */}
            <Card className="p-5 border border-border/80">
              <div className="flex items-center justify-between pb-3 border-b border-border/60 mb-4">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold font-headline">Detected Exposure Categories</h3>
                </div>
                <span className="text-xs text-muted-foreground font-mono">Service Signatures</span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {(dashboardData?.category_breakdown || [
                  { category: 'RDP Exposure', count: 0 },
                  { category: 'Redis Exposure', count: 0 },
                  { category: 'PostgreSQL Exposure', count: 0 },
                  { category: 'SSH Exposure', count: 0 },
                  { category: 'Admin Interface', count: 0 },
                  { category: 'Public Service', count: 0 },
                ]).map((cat, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border border-border/60 bg-muted/20 flex items-center justify-between"
                  >
                    <span className="text-xs font-medium text-foreground truncate pr-2">{cat.category}</span>
                    <Badge variant="outline" className="font-mono text-xs font-bold shrink-0">
                      {cat.count}
                    </Badge>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Top Risky Assets Table */}
          <Card className="p-5 border border-border/80">
            <div className="flex items-center justify-between pb-3 border-b border-border/60 mb-4">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold font-headline">Top Risky Assets (Prioritized)</h3>
              </div>
              <span className="text-xs text-muted-foreground font-mono">Sorted by Maximum Risk</span>
            </div>

            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/30">
                    <TableHead>Asset / Hostname</TableHead>
                    <TableHead>Platform</TableHead>
                    <TableHead className="text-center">Active Exposures</TableHead>
                    <TableHead className="text-center">Max Risk Score</TableHead>
                    <TableHead className="text-center">Open Incidents</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {dashboardData?.top_risky_assets?.length ? (
                    dashboardData.top_risky_assets.map((asset) => (
                      <TableRow key={asset.device_id} className="hover:bg-muted/40 transition-colors">
                        <TableCell className="font-mono text-xs font-semibold text-foreground">
                          {asset.hostname || 'Unknown Host'}
                          <span className="block text-[10px] text-muted-foreground font-sans">
                            ID: {asset.device_id?.slice(0, 8)}...
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px] font-mono capitalize">
                            {asset.platform || 'server'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-center font-mono font-bold text-amber-500">
                          {asset.active_exposures}
                        </TableCell>
                        <TableCell className="text-center">
                          <RiskBadge
                            level={
                              asset.max_risk_score >= 90
                                ? 'critical'
                                : asset.max_risk_score >= 70
                                ? 'high'
                                : asset.max_risk_score >= 40
                                ? 'medium'
                                : 'low'
                            }
                            score={asset.max_risk_score}
                            size="sm"
                          />
                        </TableCell>
                        <TableCell className="text-center font-mono font-bold">
                          {asset.open_incidents > 0 ? (
                            <span className="text-rose-500">{asset.open_incidents}</span>
                          ) : (
                            <span className="text-muted-foreground">0</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setScanTargetScope('device');
                              setScanDeviceId(asset.device_id);
                              setIsScanModalOpen(true);
                            }}
                            className="text-xs text-primary gap-1"
                          >
                            <Play className="w-3.5 h-3.5" />
                            Scan Asset
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-muted-foreground text-xs">
                        No high-risk assets detected in fleet.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </div>
      )}

      {/* ───────────────────────────────────────────────────────────────────────
          TAB 2: EXPOSURE INVENTORY TABLE
      ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'inventory' && (
        <Card className="p-5 border border-border/80 space-y-4">
          {/* Controls & Filter Bar */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="flex flex-1 items-center gap-2 max-w-md relative">
              <Search className="w-4 h-4 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                placeholder="Search hostname, process, port, rule..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 text-xs"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {/* Severity Filter */}
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Filter className="w-3.5 h-3.5" />
                <span>Severity:</span>
                <select
                  value={filterSeverity}
                  onChange={(e) => {
                    setFilterSeverity(e.target.value);
                    setInventoryOffset(0);
                  }}
                  className="bg-card border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              {/* Status Filter */}
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span>Status:</span>
                <select
                  value={filterStatus}
                  onChange={(e) => {
                    setFilterStatus(e.target.value);
                    setInventoryOffset(0);
                  }}
                  className="bg-card border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="all">All Statuses</option>
                  <option value="active">Active Only</option>
                  <option value="mitigated">Mitigated</option>
                  <option value="suppressed">Suppressed</option>
                </select>
              </div>

              {/* Page Size */}
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span>Limit:</span>
                <select
                  value={inventoryLimit}
                  onChange={(e) => {
                    setInventoryLimit(Number(e.target.value));
                    setInventoryOffset(0);
                  }}
                  className="bg-card border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead>Host / Device</TableHead>
                  <TableHead>Port & Protocol</TableHead>
                  <TableHead>Process</TableHead>
                  <TableHead>Exposure Rule</TableHead>
                  <TableHead>MITRE Technique</TableHead>
                  <TableHead className="text-center">Risk Score</TableHead>
                  <TableHead>First Seen</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead className="text-center">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exposures.length > 0 ? (
                  exposures.map((exp) => (
                    <TableRow
                      key={exp.id}
                      onClick={() => setSelectedExposureId(exp.id)}
                      className="cursor-pointer hover:bg-muted/40 transition-colors"
                    >
                      <TableCell className="font-mono text-xs font-semibold text-foreground">
                        {exp.hostname || 'Unknown'}
                        <span className="block text-[10px] text-muted-foreground font-sans">
                          {exp.platform || 'server'}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <span className="font-bold text-foreground">{exp.port}</span>
                        <span className="text-muted-foreground uppercase text-[10px] ml-1">/{exp.protocol}</span>
                        <span className="block text-[10px] text-muted-foreground">{exp.bind_address}</span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground truncate max-w-[120px]">
                        {exp.process_name || 'unknown'}
                      </TableCell>
                      <TableCell className="text-xs">
                        <span className="font-medium text-foreground block">{exp.title}</span>
                        <span className="text-[10px] font-mono text-muted-foreground">{exp.rule_id}</span>
                      </TableCell>
                      <TableCell>
                        {exp.technique_id ? (
                          <Badge variant="outline" className="font-mono text-[10px] bg-primary/5 text-primary border-primary/20">
                            {exp.technique_id}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-[10px]">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        <RiskBadge level={exp.severity} score={exp.risk_score} size="sm" />
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                        {exp.first_seen_at ? new Date(exp.first_seen_at).toLocaleDateString() : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                        {exp.last_seen_at ? new Date(exp.last_seen_at).toLocaleTimeString() : '—'}
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-[10px] font-mono uppercase',
                            exp.status === 'active'
                              ? 'text-rose-500 border-rose-500/30 bg-rose-500/10'
                              : exp.status === 'mitigated'
                              ? 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10'
                              : 'text-muted-foreground border-border'
                          )}
                        >
                          {exp.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={9} className="text-center py-12">
                      <EmptyState
                        title="No Exposures Found"
                        description="Try adjusting your severity, status, or search query filters."
                      />
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
            <div>
              Showing {Math.min(inventoryOffset + 1, inventoryTotal)} to{' '}
              {Math.min(inventoryOffset + inventoryLimit, inventoryTotal)} of {inventoryTotal} exposures
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={inventoryOffset === 0}
                onClick={() => setInventoryOffset((prev) => Math.max(0, prev - inventoryLimit))}
                className="gap-1 text-xs"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={inventoryOffset + inventoryLimit >= inventoryTotal}
                onClick={() => setInventoryOffset((prev) => prev + inventoryLimit)}
                className="gap-1 text-xs"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* ───────────────────────────────────────────────────────────────────────
          TAB 3: EXPOSURE ANALYTICS
      ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'analytics' && (
        <div className="space-y-6">
          {/* Time range selector */}
          <div className="flex items-center justify-between bg-card p-4 rounded-lg border border-border">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-primary" />
              <span className="text-sm font-bold font-headline">Telemetry Analysis Window</span>
            </div>
            <div className="flex items-center gap-1.5">
              {[7, 14, 30, 90].map((days) => (
                <Button
                  key={days}
                  variant={analyticsDays === days ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setAnalyticsDays(days)}
                  className="font-mono text-xs px-3"
                >
                  {days} Days
                </Button>
              ))}
            </div>
          </div>

          {/* Performance Summary Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="p-4 border border-border">
              <span className="text-xs text-muted-foreground uppercase font-mono">Average Risk Score</span>
              <div className="text-3xl font-bold font-mono text-primary mt-1">
                {analyticsData?.summary?.avg_risk_score || 0}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Across all detected active ports</p>
            </Card>

            <Card className="p-4 border border-border">
              <span className="text-xs text-muted-foreground uppercase font-mono">Mean Time to Remediate</span>
              <div className="text-3xl font-bold font-mono text-emerald-500 mt-1">
                {analyticsData?.summary?.avg_time_to_remediate_hours || 0}h
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">From initial scan detection to closed</p>
            </Card>

            <Card className="p-4 border border-border">
              <span className="text-xs text-muted-foreground uppercase font-mono">Total Active Assets</span>
              <div className="text-3xl font-bold font-mono text-foreground mt-1">
                {analyticsData?.summary?.total_active || 0}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Requiring network firewall or port binding hardening</p>
            </Card>
          </div>

          {/* Daily Active Exposures Trend Chart */}
          <Card className="p-5 border border-border">
            <div className="flex items-center justify-between pb-3 border-b border-border/60 mb-4">
              <h3 className="text-sm font-bold font-headline">Daily Exposure Posture Trend</h3>
              <span className="text-xs text-muted-foreground font-mono">Past {analyticsDays} Days</span>
            </div>

            {/* Simple Responsive SVG Trend Chart */}
            <div className="h-48 w-full flex items-end gap-2 pt-6 px-2">
              {(analyticsData?.exposure_trend || []).map((point, idx) => {
                const max = Math.max(...(analyticsData?.exposure_trend || []).map((p) => p.active_count), 1);
                const heightPct = Math.max(10, Math.round((point.active_count / max) * 100));
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 group relative">
                    {/* Tooltip */}
                    <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute -top-8 bg-popover text-popover-foreground border border-border text-[10px] font-mono px-2 py-1 rounded shadow-lg pointer-events-none whitespace-nowrap z-20">
                      {point.date}: {point.active_count} active
                    </div>
                    <div
                      className="w-full bg-primary/70 hover:bg-primary transition-all rounded-t"
                      style={{ height: `${heightPct}%` }}
                    />
                    <span className="text-[9px] font-mono text-muted-foreground truncate w-full text-center">
                      {point.date?.slice(5)}
                    </span>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      )}

      {/* ───────────────────────────────────────────────────────────────────────
          TAB 4: FLEET SCAN MANAGEMENT
      ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'scans' && (
        <Card className="p-5 border border-border space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-border/60">
            <div>
              <h3 className="text-sm font-bold font-headline">Fleet Scan Orchestration & History</h3>
              <p className="text-xs text-muted-foreground">
                Dispatch socket and command queue scan orders to all enrolled endpoint agents.
              </p>
            </div>
            <Button size="sm" onClick={() => setIsScanModalOpen(true)} className="gap-2">
              <Play className="w-3.5 h-3.5" />
              Trigger Fleet Scan
            </Button>
          </div>

          <div className="rounded-lg border border-border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/30">
                  <TableHead>Command / Scan ID</TableHead>
                  <TableHead>Target Hostname</TableHead>
                  <TableHead>Command Type</TableHead>
                  <TableHead>Initiated At</TableHead>
                  <TableHead>Completed At</TableHead>
                  <TableHead className="text-center">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.length > 0 ? (
                  scans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell className="font-mono text-xs font-medium text-foreground">
                        {scan.id?.slice(0, 13)}...
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground">
                        {scan.hostname || 'Fleet-wide (all)'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {scan.command_type || 'scan_attack_surface'}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {scan.initiated_at ? new Date(scan.initiated_at).toLocaleString() : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In Progress'}
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-[10px] font-mono uppercase',
                            scan.status === 'completed'
                              ? 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10'
                              : scan.status === 'pending'
                              ? 'text-amber-500 border-amber-500/30 bg-amber-500/10'
                              : scan.status === 'failed'
                              ? 'text-rose-500 border-rose-500/30 bg-rose-500/10'
                              : 'text-sky-500 border-sky-500/30 bg-sky-500/10'
                          )}
                        >
                          {scan.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground text-xs">
                      No scan history logged yet. Click &apos;Trigger Fleet Scan&apos; above.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </Card>
      )}

      {/* ───────────────────────────────────────────────────────────────────────
          TAB 5: RESPONSE ACTION CENTER (SHADOW MODE)
      ─────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'response-actions' && (
        <div className="space-y-4">
          {/* Shadow Mode Safety Banner */}
          <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
            <Lock className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="text-xs font-bold font-headline text-amber-500 uppercase tracking-wide">
                Shadow Mode Enforcement — Zero Automated Destructive Actions
              </h4>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Response actions proposed by the policy engine remain strictly in proposed status. Manual analyst
                approval is mandatory before firewall reconfiguration, port closure, or agent isolation is executed.
              </p>
            </div>
          </div>

          <Card className="p-5 border border-border">
            <div className="flex items-center justify-between pb-3 border-b border-border/60 mb-4">
              <h3 className="text-sm font-bold font-headline">Proposed & Staged Policy Responses</h3>
              <span className="text-xs text-muted-foreground font-mono">
                {actions.filter((a) => a.status === 'proposed').length} Awaiting Review
              </span>
            </div>

            <div className="rounded-lg border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/30">
                    <TableHead>Action Type</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead>Target Incident</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead className="text-center">Status</TableHead>
                    <TableHead className="text-right">Analyst Decision</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {actions.length > 0 ? (
                    actions.map((act) => {
                      const Icon = ACTION_ICONS[act.action_type] || Lock;
                      return (
                        <TableRow key={act.id}>
                          <TableCell className="font-mono text-xs font-semibold text-foreground">
                            <div className="flex items-center gap-2">
                              <Icon className="w-4 h-4 text-primary" />
                              <span>{act.action_type}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="font-mono text-[10px] uppercase text-amber-500 border-amber-500/30">
                              {act.action_mode || 'shadow'}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {act.incident_id?.slice(0, 13)}...
                          </TableCell>
                          <TableCell className="font-mono text-[11px] text-muted-foreground">
                            {act.created_at ? new Date(act.created_at).toLocaleString() : '—'}
                          </TableCell>
                          <TableCell className="text-center">
                            <Badge
                              variant="outline"
                              className={cn(
                                'text-[10px] font-mono uppercase',
                                act.status === 'approved'
                                  ? 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10'
                                  : act.status === 'rejected'
                                  ? 'text-rose-500 border-rose-500/30 bg-rose-500/10'
                                  : act.status === 'executed'
                                  ? 'text-sky-500 border-sky-500/30 bg-sky-500/10'
                                  : 'text-amber-500 border-amber-500/30 bg-amber-500/10'
                              )}
                            >
                              {act.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            {act.status === 'proposed' ? (
                              <div className="flex items-center justify-end gap-1.5">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setSelectedActionForApproval(act);
                                    setApprovalDecision('approve');
                                  }}
                                  className="text-xs text-emerald-500 hover:text-emerald-400 gap-1 border-emerald-500/30 hover:bg-emerald-500/10"
                                >
                                  <CheckCircle2 className="w-3.5 h-3.5" /> Approve
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    setSelectedActionForApproval(act);
                                    setApprovalDecision('reject');
                                  }}
                                  className="text-xs text-rose-500 hover:text-rose-400 gap-1 border-rose-500/30 hover:bg-rose-500/10"
                                >
                                  <XCircle className="w-3.5 h-3.5" /> Reject
                                </Button>
                              </div>
                            ) : (
                              <span className="text-[11px] font-mono text-muted-foreground">
                                {act.approved_at ? `Reviewed: ${new Date(act.approved_at).toLocaleDateString()}` : 'Processed'}
                              </span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  ) : (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-muted-foreground text-xs">
                        No proposed response actions staged in policy engine.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </div>
      )}

      {/* ───────────────────────────────────────────────────────────────────────
          EXPOSURE DETAILS DRAWER (FEATURE 3)
      ─────────────────────────────────────────────────────────────────────── */}
      <Drawer
        isOpen={Boolean(selectedExposureId)}
        onClose={() => setSelectedExposureId(null)}
        title={exposureDetail?.title || 'Exposure Finding Details'}
        subtitle={`ID: ${selectedExposureId || ''}`}
        size="xl"
      >
        {isDetailLoading ? (
          <div className="flex items-center justify-center py-20 text-muted-foreground text-xs gap-2">
            <RefreshCw className="w-4 h-4 animate-spin" />
            Loading exposure telemetry...
          </div>
        ) : exposureDetail ? (
          <div className="space-y-6 text-xs font-sans">
            {/* Severity & Score Banner */}
            <div className="p-4 rounded-lg border border-border bg-muted/30 flex items-center justify-between">
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-muted-foreground uppercase">Assessed Severity</span>
                <div className="flex items-center gap-2">
                  <RiskBadge level={exposureDetail.severity} score={exposureDetail.risk_score} size="lg" />
                  <span className="font-mono text-sm font-bold text-foreground">
                    Score: {exposureDetail.risk_score}/100
                  </span>
                </div>
              </div>
              <Badge
                variant="outline"
                className={cn(
                  'font-mono text-xs uppercase px-2.5 py-1',
                  exposureDetail.status === 'active'
                    ? 'text-rose-500 border-rose-500/30 bg-rose-500/10'
                    : 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10'
                )}
              >
                {exposureDetail.status}
              </Badge>
            </div>

            {/* Technical Specifications */}
            <div className="space-y-2">
              <h4 className="font-bold text-xs uppercase tracking-wider text-muted-foreground font-mono">
                Technical Specifications
              </h4>
              <div className="grid grid-cols-2 gap-3 p-3.5 rounded-lg border border-border bg-card">
                <div>
                  <span className="text-muted-foreground text-[10px] block">Target Hostname</span>
                  <span className="font-mono font-bold text-foreground">{exposureDetail.hostname || '—'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block">Port / Protocol</span>
                  <span className="font-mono font-bold text-foreground">
                    {exposureDetail.port} / {exposureDetail.protocol}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block">Bind Address</span>
                  <span className="font-mono text-foreground">{exposureDetail.bind_address || '0.0.0.0'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block">Process Name</span>
                  <span className="font-mono text-foreground">{exposureDetail.process_name || 'unknown'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block">Exposure Scope</span>
                  <Badge variant="outline" className="font-mono text-[10px] uppercase text-rose-400">
                    {exposureDetail.exposure_scope || 'public'}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground text-[10px] block">Detection Rule</span>
                  <span className="font-mono text-[11px] text-foreground">{exposureDetail.rule_id}</span>
                </div>
              </div>
            </div>

            {/* Description & Remediation Advice */}
            <div className="space-y-3">
              <div className="p-3.5 rounded-lg border border-border bg-card space-y-1.5">
                <span className="text-[10px] font-mono text-muted-foreground uppercase block font-semibold">
                  Threat Description
                </span>
                <p className="text-foreground leading-relaxed text-xs">
                  {exposureDetail.description || 'Public service port listening on external network interfaces.'}
                </p>
              </div>

              <div className="p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 space-y-1.5">
                <span className="text-[10px] font-mono text-emerald-500 uppercase block font-semibold flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Prescribed Remediation
                </span>
                <p className="text-foreground leading-relaxed text-xs">
                  {exposureDetail.remediation || 'Restrict listen address to localhost or apply host firewall rules.'}
                </p>
              </div>
            </div>

            {/* MITRE ATT&CK Mapping */}
            <div className="space-y-2">
              <h4 className="font-bold text-xs uppercase tracking-wider text-muted-foreground font-mono">
                MITRE ATT&CK Mapping
              </h4>
              {exposureDetail.mitre_mappings?.length ? (
                <div className="space-y-2">
                  {exposureDetail.mitre_mappings.map((m, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg border border-border bg-card flex items-center justify-between"
                    >
                      <div className="space-y-0.5">
                        <span className="font-mono font-bold text-primary">{m.technique_id}</span>
                        <span className="block text-foreground font-medium">{m.technique_name}</span>
                      </div>
                      <a
                        href={`https://attack.mitre.org/techniques/${m.technique_id.replace(/\./g, '/')}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-primary hover:text-primary/80 flex items-center gap-1 text-[11px] font-mono"
                      >
                        Explore <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 rounded-lg border border-border text-muted-foreground text-center">
                  No MITRE techniques linked to this finding.
                </div>
              )}
            </div>

            {/* Lifecycle Timeline */}
            <div className="space-y-2">
              <h4 className="font-bold text-xs uppercase tracking-wider text-muted-foreground font-mono">
                Exposure Lifecycle
              </h4>
              <div className="p-3 rounded-lg border border-border bg-card space-y-2 text-[11px] font-mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">First Seen:</span>
                  <span className="text-foreground">
                    {exposureDetail.first_seen_at ? new Date(exposureDetail.first_seen_at).toLocaleString() : '—'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Last Seen:</span>
                  <span className="text-foreground">
                    {exposureDetail.last_seen_at ? new Date(exposureDetail.last_seen_at).toLocaleString() : '—'}
                  </span>
                </div>
                {exposureDetail.mitigated_at && (
                  <div className="flex justify-between text-emerald-500">
                    <span>Mitigated At:</span>
                    <span>{new Date(exposureDetail.mitigated_at).toLocaleString()}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Correlated SOC Incident & Triage Controls */}
            {exposureDetail.incident_id && (
              <div className="space-y-3 pt-3 border-t border-border">
                <h4 className="font-bold text-xs uppercase tracking-wider text-muted-foreground font-mono flex items-center justify-between">
                  <span>Linked SOC Incident</span>
                  <Badge variant="outline" className="font-mono text-[10px] uppercase">
                    {exposureDetail.incident?.status || 'open'}
                  </Badge>
                </h4>

                <div className="p-3.5 rounded-lg border border-border bg-card space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Incident ID:</span>
                    <span className="font-mono text-foreground font-bold">
                      {exposureDetail.incident_id?.slice(0, 18)}...
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-muted-foreground text-[10px] uppercase font-mono block">
                      Update Incident Status
                    </label>
                    <div className="flex items-center gap-2">
                      <select
                        value={incidentTriageStatus}
                        onChange={(e) => setIncidentTriageStatus(e.target.value)}
                        className="bg-muted border border-border rounded px-2.5 py-1.5 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary flex-1"
                      >
                        <option value="open">Open</option>
                        <option value="investigating">Investigating</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-muted-foreground text-[10px] uppercase font-mono block">
                      Analyst Investigation Note
                    </label>
                    <Input
                      placeholder="Add analyst note or verification details..."
                      value={incidentTriageNote}
                      onChange={(e) => setIncidentTriageNote(e.target.value)}
                      className="text-xs"
                    />
                  </div>

                  <Button
                    size="sm"
                    onClick={handleUpdateIncident}
                    disabled={isUpdatingIncident}
                    className="w-full gap-2 text-xs"
                  >
                    {isUpdatingIncident ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    Save Incident Update
                  </Button>
                </div>
              </div>
            )}
          </div>
        ) : null}
      </Drawer>

      {/* ───────────────────────────────────────────────────────────────────────
          TRIGGER SCAN MODAL
      ─────────────────────────────────────────────────────────────────────── */}
      <Dialog open={isScanModalOpen} onOpenChange={setIsScanModalOpen}>
        <DialogContent className="sm:max-w-md">
          <form onSubmit={handleTriggerScanSubmit} className="space-y-4">
            <DialogHeader>
              <DialogTitle className="text-base font-bold font-headline flex items-center gap-2">
                <Play className="w-4 h-4 text-primary fill-current" />
                Trigger Attack Surface Fleet Scan
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground">
                Dispatches an asynchronous inspection order to enrolled agent nodes to audit active listening ports and exposure scopes.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 py-2 text-xs">
              <div className="space-y-1.5">
                <label className="font-semibold text-foreground">Target Scope</label>
                <select
                  value={scanTargetScope}
                  onChange={(e) => setScanTargetScope(e.target.value)}
                  className="w-full bg-card border border-border rounded px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="all">Entire Fleet / All Active Agents</option>
                  <option value="device">Specific Device / Endpoint</option>
                </select>
              </div>

              {scanTargetScope === 'device' && (
                <div className="space-y-1.5">
                  <label className="font-semibold text-foreground">Target Device ID (UUID)</label>
                  <Input
                    placeholder="Enter device UUID..."
                    value={scanDeviceId}
                    onChange={(e) => setScanDeviceId(e.target.value)}
                    required
                    className="font-mono text-xs"
                  />
                </div>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" size="sm" onClick={() => setIsScanModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={isTriggeringScan} className="gap-2">
                {isTriggeringScan ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Dispatch Scan Command
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ───────────────────────────────────────────────────────────────────────
          RESPONSE ACTION APPROVAL MODAL
      ─────────────────────────────────────────────────────────────────────── */}
      <Dialog
        open={Boolean(selectedActionForApproval)}
        onOpenChange={(open) => !open && setSelectedActionForApproval(null)}
      >
        <DialogContent className="sm:max-w-md">
          <div className="space-y-4">
            <DialogHeader>
              <DialogTitle className="text-base font-bold font-headline flex items-center gap-2">
                <Lock className="w-4 h-4 text-amber-500" />
                Analyst Policy Decision: {selectedActionForApproval?.action_type}
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground">
                Confirm whether to approve this shadow response action for enforcement or reject it.
              </DialogDescription>
            </DialogHeader>

            <div className="p-3.5 rounded-lg border border-border bg-muted/30 space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Action ID:</span>
                <span className="text-foreground">{selectedActionForApproval?.id?.slice(0, 16)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Decision:</span>
                <Badge
                  variant="outline"
                  className={cn(
                    'font-mono text-[10px] uppercase font-bold',
                    approvalDecision === 'approve'
                      ? 'text-emerald-500 border-emerald-500/30'
                      : 'text-rose-500 border-rose-500/30'
                  )}
                >
                  {approvalDecision}
                </Badge>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground">Analyst Reason / Justification</label>
              <Input
                placeholder="Enter justification for forensic audit trail..."
                value={approvalReason}
                onChange={(e) => setApprovalReason(e.target.value)}
                className="text-xs"
              />
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setSelectedActionForApproval(null)}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleSubmitActionDecision}
                disabled={isSubmittingApproval}
                className={cn(
                  'gap-1.5 font-semibold text-white',
                  approvalDecision === 'approve'
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : 'bg-rose-600 hover:bg-rose-500'
                )}
              >
                {isSubmittingApproval ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : approvalDecision === 'approve' ? (
                  <CheckCircle2 className="w-3.5 h-3.5" />
                ) : (
                  <XCircle className="w-3.5 h-3.5" />
                )}
                Confirm {approvalDecision === 'approve' ? 'Approval' : 'Rejection'}
              </Button>
            </DialogFooter>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AttackSurfacePage;
