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
} from '../components/ui';
import {
  Zap,
  Activity,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Search,
  Filter,
  ExternalLink,
  Flame,
  Clock,
  ChevronLeft,
  ChevronRight,
  Copy,
  Check,
  Radio,
  Play,
  Layers,
} from 'lucide-react';
import { ddosService } from '../services/ddosService';
import { toast } from 'sonner';

const SCAN_TYPE_OPTIONS = [
  {
    value: 'request_spike',
    label: 'Request Spike',
    description: 'High frequency request volume (>500 requests per IP in 5m)',
    defaultWindow: 5,
  },
  {
    value: 'post_flood',
    label: 'POST Flood',
    description: 'HTTP POST volumetric flood to endpoint (>100 POST in 5m)',
    defaultWindow: 5,
    needsEndpoint: true,
  },
  {
    value: 'login_abuse',
    label: 'Login Abuse',
    description: 'Credential abuse pattern (>10 failed attempts in 15m)',
    defaultWindow: 15,
  },
  {
    value: 'ip_flooding',
    label: 'IP Flooding',
    description: 'Single-source IP burst flooding (>20 requests in 5m)',
    defaultWindow: 5,
  },
  {
    value: 'distributed_ddos',
    label: 'Distributed DDoS',
    description: 'Multi-source distributed swarm (>20 distinct IPs & >400 requests)',
    defaultWindow: 5,
  },
];

export function DDoSPage() {
  const navigate = useNavigate();
  const { user, isAdmin } = useAuth();

  // State: Threat History
  const [threats, setThreats] = useState([]);
  const [totalThreats, setTotalThreats] = useState(0);
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [isLoadingThreats, setIsLoadingThreats] = useState(true);
  const [threatsError, setThreatsError] = useState(null);
  const [filterType, setFilterType] = useState('all');

  // State: Manual Scan Console
  const [scanType, setScanType] = useState('request_spike');
  const [scanEndpoint, setScanEndpoint] = useState('');
  const [scanWindowMinutes, setScanWindowMinutes] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);

  // State: Copy feedback
  const [copiedIp, setCopiedIp] = useState(null);

  // ─────────────────────────────────────────────────────────────────────────────
  // 1. Fetch Threats History
  // ─────────────────────────────────────────────────────────────────────────────
  const fetchThreats = useCallback(async () => {
    setIsLoadingThreats(true);
    setThreatsError(null);
    try {
      const params = {
        limit,
        offset,
      };
      if (filterType !== 'all') {
        params.scan_type = filterType;
      }

      const res = await ddosService.getThreats(params);
      setThreats(res?.threats || []);
      setTotalThreats(res?.total || 0);
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to retrieve DDoS threats';
      setThreatsError(msg);
      toast.error('DDoS Error', { description: msg });
    } finally {
      setIsLoadingThreats(false);
    }
  }, [limit, offset, filterType]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. Trigger Heuristic Scan
  // ─────────────────────────────────────────────────────────────────────────────
  const handleRunScan = async (e) => {
    e?.preventDefault();
    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    try {
      const payload = {
        scan_type: scanType,
      };

      if (scanEndpoint.trim()) {
        payload.endpoint = scanEndpoint.trim();
      }

      if (scanWindowMinutes && !isNaN(parseInt(scanWindowMinutes, 10))) {
        payload.window_minutes = Math.max(1, parseInt(scanWindowMinutes, 10));
      }

      const res = await ddosService.runScan(payload);
      setScanResult(res);

      if (res?.threats?.length > 0) {
        toast.warning('DDoS Scan Completed', {
          description: `Identified ${res.threats.length} threat(s) exceeding heuristic thresholds.`,
        });
      } else {
        toast.success('DDoS Scan Completed', {
          description: 'No threshold violations detected.',
        });
      }

      // Refresh threat history table in background
      fetchThreats();
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Failed to execute detection scan';
      setScanError(msg);
      toast.error('Scan Failed', { description: msg });
    } finally {
      setIsScanning(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. Clipboard helper
  // ─────────────────────────────────────────────────────────────────────────────
  const handleCopyIp = (ip) => {
    if (!ip) return;
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    toast.success('IP copied to clipboard');
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. Real KPI Metrics (Strictly from returned backend data)
  // ─────────────────────────────────────────────────────────────────────────────
  const metrics = useMemo(() => {
    let violationCount = 0;
    const typeBreakdown = {
      request_spike: 0,
      post_flood: 0,
      login_abuse: 0,
      ip_flooding: 0,
      distributed_ddos: 0,
    };

    threats.forEach((t) => {
      if (t.threshold_exceeded) {
        violationCount++;
      }
      if (typeBreakdown[t.metric_type] !== undefined) {
        typeBreakdown[t.metric_type]++;
      }
    });

    return {
      totalRecorded: totalThreats,
      loadedViolations: violationCount,
      typeBreakdown,
    };
  }, [threats, totalThreats]);

  // Helper: Format metric type badge
  const renderMetricBadge = (type) => {
    switch (type) {
      case 'request_spike':
        return (
          <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30 font-mono text-[11px]">
            Request Spike
          </Badge>
        );
      case 'post_flood':
        return (
          <Badge variant="outline" className="bg-rose-500/10 text-rose-400 border-rose-500/30 font-mono text-[11px]">
            POST Flood
          </Badge>
        );
      case 'login_abuse':
        return (
          <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/30 font-mono text-[11px]">
            Login Abuse
          </Badge>
        );
      case 'ip_flooding':
        return (
          <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 font-mono text-[11px]">
            IP Flooding
          </Badge>
        );
      case 'distributed_ddos':
        return (
          <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/30 font-mono text-[11px]">
            Distributed DDoS
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="bg-muted text-muted-foreground font-mono text-[11px]">
            {type || 'Unknown'}
          </Badge>
        );
    }
  };

  // ─────────────────────────────────────────────────────────────────────────────
  // Non-Admin Access Guard
  // ─────────────────────────────────────────────────────────────────────────────
  if (!isAdmin) {
    return (
      <div className="p-8 max-w-4xl mx-auto">
        <Alert variant="destructive" className="border-destructive/40 bg-destructive/10">
          <ShieldAlert className="w-5 h-5 text-destructive" />
          <div className="ml-3">
            <h3 className="text-base font-semibold text-destructive">Administrative Access Required</h3>
            <p className="text-sm text-destructive/80 mt-1">
              DDoS Heuristic Scan & Threat Intelligence is restricted to organization administrators. Your current session
              does not possess the required <code className="font-mono text-xs">admin</code> privilege.
            </p>
          </div>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* ─────────────────────────────────────────────────────────────────────────────
          1. Header Banner
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Zap className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                DDoS Threat Monitoring & Heuristics
                <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 font-mono text-xs font-normal">
                  Phase 6A
                </Badge>
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Execute manual heuristic pattern detection scans and inspect tenant-scoped DDoS threat history.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchThreats}
            disabled={isLoadingThreats}
            className="gap-2 border-border/80 hover:bg-muted/60"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoadingThreats && 'animate-spin text-primary')} />
            Refresh History
          </Button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          2. Overview KPI Cards (Real Data Only)
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Total Recorded Threat Events */}
        <div className="p-4 rounded-xl border border-border/70 bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Total Logged Threats</span>
            <Activity className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-foreground">
            {isLoadingThreats ? <Skeleton className="h-8 w-14" /> : metrics.totalRecorded}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">Tenant organization scope</p>
        </div>

        {/* Loaded Threshold Violations */}
        <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-500/5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-rose-400">Threshold Violations</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-rose-400">
            {isLoadingThreats ? <Skeleton className="h-8 w-14" /> : metrics.loadedViolations}
          </div>
          <p className="text-[11px] text-rose-500/80 mt-1">
            In current page ({threats.length} loaded records)
          </p>
        </div>

        {/* Top Active Pattern */}
        <div className="p-4 rounded-xl border border-border/70 bg-card/60 backdrop-blur-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Request Spikes</span>
            <Radio className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-foreground">
            {isLoadingThreats ? <Skeleton className="h-8 w-14" /> : metrics.typeBreakdown.request_spike}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">&gt;500 requests/5m</p>
        </div>

        {/* Distributed Swarms */}
        <div className="p-4 rounded-xl border border-purple-500/20 bg-purple-500/5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-purple-400">Distributed Swarms</span>
            <Layers className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-bold tracking-tight text-purple-400">
            {isLoadingThreats ? <Skeleton className="h-8 w-14" /> : metrics.typeBreakdown.distributed_ddos}
          </div>
          <p className="text-[11px] text-purple-500/80 mt-1">Multi-source coordinated attack</p>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          3. DDoS Scan Console Panel
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="rounded-xl border border-border/70 bg-card p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border/50">
          <div>
            <h3 className="text-base font-semibold text-foreground flex items-center gap-2">
              <Play className="w-4 h-4 text-primary fill-primary" />
              Run DDoS Heuristic Detection Scan
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Targeted server-side heuristic analysis across sliding audit and volumetric metric windows.
            </p>
          </div>
        </div>

        <form onSubmit={handleRunScan} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Scan Type Selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground">
                Detection Pattern (scan_type) <span className="text-destructive">*</span>
              </label>
              <select
                value={scanType}
                onChange={(e) => {
                  setScanType(e.target.value);
                  const selectedOpt = SCAN_TYPE_OPTIONS.find((o) => o.value === e.target.value);
                  if (selectedOpt) {
                    setScanWindowMinutes(String(selectedOpt.defaultWindow));
                  }
                }}
                className="w-full h-9 text-xs rounded-md border border-input bg-background px-3 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {SCAN_TYPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-muted-foreground">
                {SCAN_TYPE_OPTIONS.find((o) => o.value === scanType)?.description}
              </p>
            </div>

            {/* Target Endpoint Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground">
                Target Endpoint Path (Optional)
              </label>
              <Input
                value={scanEndpoint}
                onChange={(e) => setScanEndpoint(e.target.value)}
                placeholder="/api/v1/auth/login"
                className="h-9 text-xs font-mono"
              />
              <p className="text-[11px] text-muted-foreground">
                Filter analysis by target route (e.g. for POST flood detection).
              </p>
            </div>

            {/* Time Window Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground">
                Observation Window (Minutes)
              </label>
              <Input
                type="number"
                min={1}
                max={120}
                value={scanWindowMinutes}
                onChange={(e) => setScanWindowMinutes(e.target.value)}
                placeholder={scanType === 'login_abuse' ? '15' : '5'}
                className="h-9 text-xs font-mono"
              />
              <p className="text-[11px] text-muted-foreground">
                Sliding retrospective timeframe (default: {scanType === 'login_abuse' ? '15m' : '5m'}).
              </p>
            </div>
          </div>

          {/* Form Actions */}
          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-muted-foreground">
              Scan execution automatically registers open incidents for confirmed threshold violations.
            </span>
            <Button
              type="submit"
              disabled={isScanning}
              className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 h-9 px-4 text-xs"
            >
              <Play className={cn('w-3.5 h-3.5 fill-current', isScanning && 'animate-spin')} />
              {isScanning ? 'Analyzing Telemetry...' : 'Execute Heuristic Scan'}
            </Button>
          </div>
        </form>

        {/* Scan Error */}
        {scanError && (
          <Alert variant="destructive" className="py-2.5">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs ml-2 font-medium">{scanError}</span>
          </Alert>
        )}

        {/* ─────────────────────────────────────────────────────────────────────────────
            4. Scan Result Panel (STEP 5)
        ───────────────────────────────────────────────────────────────────────────── */}
        {scanResult && (
          <div className="rounded-lg border border-border/60 bg-muted/20 p-4 space-y-3 mt-3">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-foreground">Scan Results:</span>
                {renderMetricBadge(scanResult.metric_type)}
              </div>
              <div className="text-xs text-muted-foreground">
                Incidents Created:{' '}
                <span className="font-semibold text-foreground">{scanResult.incidents_created || 0}</span>
              </div>
            </div>

            {scanResult.threats?.length === 0 ? (
              <div className="p-4 text-center rounded-md bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 text-xs">
                <CheckCircle2 className="w-5 h-5 mx-auto mb-1 text-emerald-400" />
                No threshold violations detected within the specified observation window.
              </div>
            ) : (
              <div className="space-y-2">
                <div className="text-xs text-muted-foreground font-medium">
                  Identified Threats ({scanResult.threats.length}):
                </div>
                <div className="divide-y divide-border/40 border border-border/50 rounded-lg overflow-hidden bg-card/80">
                  {scanResult.threats.map((threat, idx) => (
                    <div key={idx} className="p-3 text-xs flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-semibold text-foreground">
                            {threat.source_ip || threat.target || 'Distributed Swarm'}
                          </span>
                          {threat.threshold_exceeded && (
                            <Badge variant="outline" className="bg-rose-500/10 text-rose-400 border-rose-500/30 text-[10px]">
                              Threshold Exceeded
                            </Badge>
                          )}
                          {threat.attack_type && (
                            <Badge variant="outline" className="font-mono text-[10px]">
                              {threat.attack_type}
                            </Badge>
                          )}
                        </div>

                        <div className="text-[11px] text-muted-foreground flex items-center gap-3 font-mono">
                          <span>Requests: {threat.count || threat.total_requests || 'N/A'}</span>
                          {threat.distinct_ips && <span>Distinct IPs: {threat.distinct_ips}</span>}
                          {threat.endpoint && <span>Endpoint: {threat.endpoint}</span>}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {threat.source_ip && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => navigate('/firewall')}
                            className="h-7 text-[11px] gap-1 text-amber-500 border-amber-500/30 hover:bg-amber-500/10"
                            title="Inspect in Host Firewall Console"
                          >
                            <Flame className="w-3 h-3" />
                            Firewall
                          </Button>
                        )}

                        {threat.incident_id ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => navigate('/incidents')}
                            className="h-7 text-[11px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
                            title={`Inspect Incident ${threat.incident_id}`}
                          >
                            <ExternalLink className="w-3 h-3" />
                            Incident
                          </Button>
                        ) : (
                          <span className="text-[11px] text-muted-foreground italic">No Incident ID</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ─────────────────────────────────────────────────────────────────────────────
          5. Threat History Log & Feed (STEP 6)
      ───────────────────────────────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-xl border border-border/60 bg-card/40">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-primary" />
              Recorded Threat Log
            </span>

            {/* Filter by metric_type */}
            <div className="flex items-center gap-1.5 ml-3">
              <span className="text-xs text-muted-foreground font-medium hidden sm:inline-block">Filter:</span>
              <select
                value={filterType}
                onChange={(e) => {
                  setFilterType(e.target.value);
                  setOffset(0);
                }}
                className="h-8 text-xs rounded-md border border-input bg-background/80 px-2.5 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="all">All Metric Types</option>
                <option value="request_spike">Request Spike</option>
                <option value="post_flood">POST Flood</option>
                <option value="login_abuse">Login Abuse</option>
                <option value="ip_flooding">IP Flooding</option>
                <option value="distributed_ddos">Distributed DDoS</option>
              </select>
            </div>
          </div>

          <div className="text-xs text-muted-foreground self-center shrink-0">
            Showing <span className="font-medium text-foreground">{threats.length}</span> of{' '}
            <span className="font-medium text-foreground">{totalThreats}</span> logged events
          </div>
        </div>

        {threatsError ? (
          <Alert variant="destructive" className="border-destructive/30 bg-destructive/10">
            <AlertTriangle className="w-5 h-5 text-destructive" />
            <div className="ml-3">
              <h4 className="text-sm font-semibold">Failed to Load Threat Log</h4>
              <p className="text-xs text-destructive/80 mt-0.5">{threatsError}</p>
              <Button variant="outline" size="sm" onClick={fetchThreats} className="mt-3 text-xs gap-1.5">
                <RefreshCw className="w-3 h-3" /> Retry
              </Button>
            </div>
          </Alert>
        ) : isLoadingThreats ? (
          <div className="rounded-xl border border-border/60 bg-card p-6 space-y-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-center justify-between py-2 gap-4">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-5 w-24" />
                <Skeleton className="h-4 w-28" />
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-6 w-20" />
              </div>
            ))}
          </div>
        ) : threats.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border/80 bg-card/40 p-12 text-center">
            <Zap className="w-10 h-10 text-muted-foreground/60 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-foreground">No Threat Events Logged</h3>
            <p className="text-sm text-muted-foreground max-w-md mx-auto mt-1 mb-4">
              {filterType !== 'all'
                ? 'No threats match the selected metric pattern filter. Try selecting "All Metric Types".'
                : 'Your organization has no recorded DDoS metric events. Run a heuristic scan above to detect abnormal traffic volume.'}
            </p>
            {filterType !== 'all' && (
              <Button variant="outline" size="sm" onClick={() => setFilterType('all')}>
                Reset Filter
              </Button>
            )}
          </div>
        ) : (
          <div className="rounded-xl border border-border/70 bg-card overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-border/60 bg-muted/30 text-muted-foreground font-mono uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4 font-semibold">Source IP</th>
                    <th className="py-3 px-4 font-semibold">Metric Pattern</th>
                    <th className="py-3 px-4 font-semibold">Target / Endpoint</th>
                    <th className="py-3 px-4 font-semibold">Count</th>
                    <th className="py-3 px-4 font-semibold">Threshold Status</th>
                    <th className="py-3 px-4 font-semibold">Timestamp</th>
                    <th className="py-3 px-4 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {threats.map((threat) => {
                    const linkedIncidentId = threat.metadata?.incident_id || threat.incident_id || null;
                    const isRealIp = threat.source_ip && threat.source_ip !== 'unknown' && threat.source_ip !== 'distributed_swarm';

                    return (
                      <tr key={threat.id} className="hover:bg-muted/30 transition-colors">
                        {/* Source IP */}
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5 font-mono font-medium text-foreground">
                            <span>{threat.source_ip || '—'}</span>
                            {isRealIp && (
                              <button
                                onClick={() => handleCopyIp(threat.source_ip)}
                                className="text-muted-foreground hover:text-foreground p-0.5"
                                title="Copy Source IP"
                              >
                                {copiedIp === threat.source_ip ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            )}
                          </div>
                        </td>

                        {/* Metric Pattern */}
                        <td className="py-3 px-4">{renderMetricBadge(threat.metric_type)}</td>

                        {/* Target / Endpoint */}
                        <td className="py-3 px-4 font-mono text-muted-foreground text-[11px]">
                          {threat.endpoint || <span className="text-muted-foreground/60 italic">Organization Scope</span>}
                        </td>

                        {/* Request Count */}
                        <td className="py-3 px-4 font-mono font-semibold text-foreground">
                          {threat.count != null ? threat.count : '—'}
                        </td>

                        {/* Threshold Exceeded */}
                        <td className="py-3 px-4">
                          {threat.threshold_exceeded ? (
                            <Badge variant="outline" className="bg-rose-500/10 text-rose-400 border-rose-500/30 gap-1 py-0.5">
                              <AlertTriangle className="w-3 h-3 text-rose-400" />
                              Exceeded
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="bg-muted text-muted-foreground border-border gap-1 py-0.5">
                              <CheckCircle2 className="w-3 h-3 text-muted-foreground" />
                              Normal
                            </Badge>
                          )}
                        </td>

                        {/* Timestamp */}
                        <td className="py-3 px-4 text-muted-foreground text-[11px] font-mono whitespace-nowrap">
                          {threat.created_at ? formatTimestamp(threat.created_at) : '—'}
                        </td>

                        {/* Actions (STEP 7 & 8) */}
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {/* Firewall Pivot */}
                            {isRealIp && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => navigate('/firewall')}
                                className="h-7 px-2 text-[11px] gap-1 text-amber-500 border-amber-500/30 hover:bg-amber-500/10"
                                title="Navigate to Host Firewall Console"
                              >
                                <Flame className="w-3 h-3" />
                                Firewall
                              </Button>
                            )}

                            {/* Incident Link */}
                            {linkedIncidentId ? (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => navigate('/incidents')}
                                className="h-7 px-2 text-[11px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
                                title={`Inspect linked incident: ${linkedIncidentId}`}
                              >
                                <ExternalLink className="w-3 h-3" />
                                Incident
                              </Button>
                            ) : (
                              <span className="text-[11px] text-muted-foreground/60 italic px-1">
                                No Incident
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination controls */}
            {totalThreats > limit && (
              <div className="p-3 border-t border-border/50 bg-muted/20 flex items-center justify-between text-xs text-muted-foreground">
                <div>
                  Showing {offset + 1} to {Math.min(offset + limit, totalThreats)} of {totalThreats}
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
                    disabled={offset + limit >= totalThreats}
                    className="h-7 px-2"
                  >
                    Next <ChevronRight className="w-3.5 h-3.5 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default DDoSPage;
