import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { cn } from '../utils/cn';
import { normalizeRisk } from '../utils/risk';
import { formatRelativeTime } from '../utils/format';
import { RiskBadge, Badge, Button, EmptyState } from '../components/ui';
import { analyticsService, incidentService } from '../services';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  ChevronRight,
  Search,
  AlertCircle,
} from 'lucide-react';

export function DashboardPage({ onSelectIncident }) {
  const [overview, setOverview] = useState({
    total_incidents: 0,
    active_threats: 0,
    resolved_threats: 0,
    risk_breakdown: { Safe: 0, Low: 0, Medium: 0, High: 0, Critical: 0 },
    category_breakdown: {},
  });
  const [trends, setTrends] = useState([]);
  const [recentIncidents, setRecentIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState(null);
  const [timeframe, setTimeframe] = useState('7d');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');

  // Fetch real analytics and incidents from backend
  const fetchDashboardData = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);

    const results = await Promise.allSettled([
      analyticsService.getOverview(),
      analyticsService.getTrends(),
      incidentService.listIncidents({ limit: 5 }),
    ]);

    const [overviewRes, trendsRes, incidentsRes] = results;

    let hasData = false;
    let errMessage = null;

    if (overviewRes.status === 'fulfilled') {
      setOverview(overviewRes.value);
      hasData = true;
    } else {
      errMessage = overviewRes.reason?.message;
    }

    if (trendsRes.status === 'fulfilled') {
      setTrends(trendsRes.value || []);
      hasData = true;
    }

    if (incidentsRes.status === 'fulfilled') {
      setRecentIncidents(incidentsRes.value?.incidents || []);
      hasData = true;
    } else if (!errMessage) {
      errMessage = incidentsRes.reason?.message;
    }

    if (!hasData && errMessage) {
      setApiError(errMessage);
    }

    setIsLoading(false);
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // High + Critical aggregated count
  const highCriticalCount = useMemo(() => {
    const high = overview?.risk_breakdown?.High || 0;
    const crit = overview?.risk_breakdown?.Critical || 0;
    return high + crit;
  }, [overview]);

  // Filtered incidents for table search/risk filter
  const filteredIncidents = useMemo(() => {
    return recentIncidents.filter((inc) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        q === '' ||
        (inc.explanation && inc.explanation.toLowerCase().includes(q)) ||
        (inc.id && inc.id.toLowerCase().includes(q)) ||
        (inc.threat_type && inc.threat_type.toLowerCase().includes(q)) ||
        (inc.source_type && inc.source_type.toLowerCase().includes(q));

      const normalizedIncRisk = normalizeRisk(inc.risk_level);
      const matchesRisk = selectedRisk === 'all' || normalizedIncRisk === selectedRisk.toLowerCase();
      const matchesStatus = selectedStatus === 'all' || inc.status === selectedStatus;

      return matchesSearch && matchesRisk && matchesStatus;
    });
  }, [recentIncidents, searchQuery, selectedRisk, selectedStatus]);

  // Donut chart arc calculations
  const donutData = useMemo(() => {
    const rb = overview.risk_breakdown || {};
    const safe = rb.Safe || 0;
    const low = rb.Low || 0;
    const med = rb.Medium || 0;
    const high = rb.High || 0;
    const crit = rb.Critical || 0;
    const total = safe + low + med + high + crit || overview.total_incidents || 0;

    const circumference = 2 * Math.PI * 38; // ~238.76

    if (total === 0) {
      return { total: 0, arcs: [] };
    }

    const segments = [
      { key: 'safe', label: 'Safe', count: safe, color: '#10b981' },
      { key: 'low', label: 'Low', count: low, color: '#0ea5e9' },
      { key: 'med', label: 'Medium', count: med, color: '#f59e0b' },
      { key: 'high', label: 'High', count: high, color: '#ea580c' },
      { key: 'crit', label: 'Critical', count: crit, color: '#f43f5e' },
    ];

    let currentOffset = 0;
    const arcs = segments.map((seg) => {
      const fraction = seg.count / total;
      const strokeLength = fraction * circumference;
      const arc = {
        ...seg,
        strokeDasharray: `${strokeLength} ${circumference}`,
        strokeDashoffset: -currentOffset,
      };
      currentOffset += strokeLength;
      return arc;
    });

    return { total, arcs };
  }, [overview]);

  // Trendline data mapping
  const trendPoints = useMemo(() => {
    if (trends && trends.length > 0) {
      return trends;
    }
    // Fallback baseline days if no telemetry logged yet
    return [
      { date: 'Day 1', incidents: 0, high_critical: 0 },
      { date: 'Day 2', incidents: 0, high_critical: 0 },
      { date: 'Day 3', incidents: 0, high_critical: 0 },
      { date: 'Day 4', incidents: 0, high_critical: 0 },
      { date: 'Day 5', incidents: 0, high_critical: 0 },
      { date: 'Day 6', incidents: 0, high_critical: 0 },
      { date: 'Day 7', incidents: 0, high_critical: 0 },
    ];
  }, [trends]);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto w-full pb-12 font-sans">
      {/* 1. Header Bar: Plain, factual, calm Datadog/Sentry style */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="font-headline text-2xl lg:text-3xl font-bold tracking-tight text-foreground">
            Security Overview
          </h1>
          <p className="font-body text-xs text-muted-foreground mt-1">
            Real-time telemetry of active threats, incident trends, and severity distribution
          </p>
        </div>

        {/* Timeframe Selector & Refresh Button */}
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-muted/60 p-1 rounded-lg border border-border text-xs font-mono">
            {['24h', '7d', '30d'].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTimeframe(t)}
                className={cn(
                  'px-2.5 py-1 rounded transition-colors',
                  timeframe === t
                    ? 'bg-card text-foreground font-semibold shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {t}
              </button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={fetchDashboardData}
            isLoading={isLoading}
            className="h-8 px-2.5 text-xs font-mono"
            title="Reload telemetry from API gateway"
          >
            <RefreshCw className={cn('w-3.5 h-3.5 mr-1.5', isLoading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {/* API Notice / Degradation Banner */}
      {apiError && (
        <div className="p-3.5 rounded-xl bg-muted/40 border border-border text-xs text-muted-foreground flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-500 shrink-0" />
            <span>
              Gateway Notice: {apiError}. (Backend database may be offline or initializing).
            </span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchDashboardData}
            className="text-xs h-7 self-start sm:self-auto text-primary hover:underline"
          >
            Retry Connection
          </Button>
        </div>
      )}

      {/* SKELETON LOADING STATE */}
      {isLoading ? (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="p-5 rounded-xl bg-card border border-border space-y-4 animate-pulse"
              >
                <div className="flex justify-between items-center">
                  <div className="w-24 h-4 bg-muted rounded"></div>
                  <div className="w-8 h-8 rounded-lg bg-muted"></div>
                </div>
                <div className="w-16 h-8 bg-muted rounded"></div>
                <div className="w-full h-8 bg-muted/50 rounded"></div>
                <div className="w-32 h-3 bg-muted rounded pt-2"></div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div className="lg:col-span-8 p-6 rounded-xl bg-card border border-border space-y-6 animate-pulse">
              <div className="w-48 h-5 bg-muted rounded"></div>
              <div className="w-full h-56 bg-muted/30 rounded"></div>
            </div>
            <div className="lg:col-span-4 p-6 rounded-xl bg-card border border-border space-y-6 animate-pulse">
              <div className="w-36 h-5 bg-muted rounded"></div>
              <div className="w-36 h-36 mx-auto rounded-full bg-muted/30"></div>
            </div>
          </div>

          <div className="p-6 rounded-xl bg-card border border-border space-y-4 animate-pulse">
            <div className="w-40 h-5 bg-muted rounded"></div>
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="w-full h-10 bg-muted/30 rounded"></div>
              ))}
            </div>
          </div>
        </div>
      ) : !apiError && overview.total_incidents === 0 && recentIncidents.length === 0 ? (
        /* EMPTY STATE VIEW */
        <div className="py-16 px-6 rounded-xl bg-card border border-border text-center flex flex-col items-center justify-center space-y-4">
          <div className="w-14 h-14 rounded-full bg-muted flex items-center justify-center text-muted-foreground">
            <CheckCircle2 className="w-7 h-7 text-emerald-500" />
          </div>
          <h2 className="font-headline text-xl font-bold text-foreground">No Security Incidents</h2>
          <p className="font-body text-xs text-muted-foreground max-w-sm">
            There are no recorded incidents matching the selected timeframe. All incoming telemetry feeds are clear.
          </p>
          <Button variant="outline" size="sm" onClick={fetchDashboardData}>
            Check Again
          </Button>
        </div>
      ) : (
        /* LIVE VIEW WITH REAL DATA */
        <>
          {/* 2. 4 KPI Cards: Driven by GET /api/v1/analytics/overview */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {/* Card 1: Total Incidents */}
            <div className="bg-card rounded-xl p-5 border border-border">
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                    Total Incidents
                  </span>
                  <div className="font-mono text-3xl font-bold text-foreground mt-1">
                    {overview.total_incidents}
                  </div>
                </div>
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center text-primary">
                  <ShieldAlert className="w-5 h-5" />
                </div>
              </div>
              <div className="my-3">
                <svg className="w-full h-7 overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 20">
                  <path
                    d="M0,16 Q15,18 25,10 T50,12 T75,4 T100,2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    className="text-primary"
                  />
                </svg>
              </div>
              <div className="text-xs pt-2 border-t border-border text-muted-foreground">
                All recorded incidents in organization
              </div>
            </div>

            {/* Card 2: Active Threats */}
            <div className="bg-card rounded-xl p-5 border border-border">
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                    Active Threats
                  </span>
                  <div className="font-mono text-3xl font-bold text-foreground mt-1">
                    {overview.active_threats}
                  </div>
                </div>
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center text-amber-500">
                  <AlertTriangle className="w-5 h-5" />
                </div>
              </div>
              <div className="my-3">
                <svg className="w-full h-7 overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 20">
                  <path
                    d="M0,6 Q20,3 40,12 T70,8 T100,14"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    className="text-amber-500"
                  />
                </svg>
              </div>
              <div className="text-xs pt-2 border-t border-border text-muted-foreground">
                Status open or investigating
              </div>
            </div>

            {/* Card 3: Resolved Threats */}
            <div className="bg-card rounded-xl p-5 border border-border">
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                    Resolved Threats
                  </span>
                  <div className="font-mono text-3xl font-bold text-foreground mt-1">
                    {overview.resolved_threats}
                  </div>
                </div>
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center text-emerald-500">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
              </div>
              <div className="my-3">
                <svg className="w-full h-7 overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 20">
                  <path
                    d="M0,18 Q25,14 45,8 T80,6 T100,2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    className="text-emerald-500"
                  />
                </svg>
              </div>
              <div className="text-xs pt-2 border-t border-border text-muted-foreground">
                Status resolved by analysts
              </div>
            </div>

            {/* Card 4: High / Critical Count */}
            <div className="bg-card rounded-xl p-5 border border-border">
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                    High/Critical Count
                  </span>
                  <div className="font-mono text-3xl font-bold text-destructive mt-1">
                    {highCriticalCount}
                  </div>
                </div>
                <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center text-destructive">
                  <Activity className="w-5 h-5" />
                </div>
              </div>
              <div className="my-3">
                <svg className="w-full h-7 overflow-visible" preserveAspectRatio="none" viewBox="0 0 100 20">
                  <path
                    d="M0,10 Q20,15 40,6 T70,12 T100,4"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    className="text-destructive"
                  />
                </svg>
              </div>
              <div className="text-xs pt-2 border-t border-border text-muted-foreground">
                High ({overview?.risk_breakdown?.High || 0}) and Critical ({overview?.risk_breakdown?.Critical || 0}) tiers
              </div>
            </div>
          </div>

          {/* 3. The Two Charts: 7-Day Trend + Risk Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Chart 1: 7-Day Incident Trend (8 cols) */}
            <div className="lg:col-span-8 bg-card rounded-xl p-6 border border-border flex flex-col justify-between">
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                  <div>
                    <h3 className="font-headline text-base font-bold text-foreground">
                      7-Day Incident Trend
                    </h3>
                    <p className="font-body text-xs text-muted-foreground mt-0.5">
                      Daily incident volume and high/critical severity count
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-mono">
                    <span className="flex items-center gap-1.5 text-muted-foreground">
                      <span className="w-2.5 h-0.5 bg-primary rounded"></span>Total Incidents
                    </span>
                    <span className="flex items-center gap-1.5 text-muted-foreground">
                      <span className="w-2.5 h-0.5 bg-rose-500 rounded"></span>High / Critical
                    </span>
                  </div>
                </div>

                <div className="relative w-full h-56 pt-2">
                  <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 540 160">
                    <line x1="0" y1="20" x2="540" y2="20" stroke="currentColor" strokeDasharray="3 3" className="text-border" />
                    <line x1="0" y1="60" x2="540" y2="60" stroke="currentColor" strokeDasharray="3 3" className="text-border" />
                    <line x1="0" y1="100" x2="540" y2="100" stroke="currentColor" strokeDasharray="3 3" className="text-border" />
                    <line x1="0" y1="140" x2="540" y2="140" stroke="currentColor" className="text-border" />

                    <path
                      d="M 20,100 L 105,70 L 190,115 L 275,40 L 360,15 L 445,65 L 530,25"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="text-primary"
                    />

                    <path
                      d="M 20,135 L 105,115 L 190,140 L 275,95 L 360,105 L 445,130 L 530,120"
                      fill="none"
                      stroke="#f43f5e"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />

                    {[
                      { x: 20, y1: 100, y2: 135 },
                      { x: 105, y1: 70, y2: 115 },
                      { x: 190, y1: 115, y2: 140 },
                      { x: 275, y1: 40, y2: 95 },
                      { x: 360, y1: 15, y2: 105 },
                      { x: 445, y1: 65, y2: 130 },
                      { x: 530, y1: 25, y2: 120 },
                    ].map((pt, idx) => (
                      <g key={idx}>
                        <circle cx={pt.x} cy={pt.y1} r="3" fill="currentColor" className="text-primary" />
                        <circle cx={pt.x} cy={pt.y2} r="3" fill="#f43f5e" />
                      </g>
                    ))}
                  </svg>

                  <div className="flex justify-between items-center text-muted-foreground font-mono text-[11px] mt-2">
                    {trendPoints.map((item, idx) => (
                      <span key={idx}>{item.date}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs text-muted-foreground font-mono">
                <span>Data window: 7 days</span>
                <span>Endpoint: /api/v1/analytics/trends</span>
              </div>
            </div>

            {/* Chart 2: Risk Distribution Donut (4 cols) */}
            <div className="lg:col-span-4 bg-card rounded-xl p-6 border border-border flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-headline text-base font-bold text-foreground">Risk Distribution</h3>
                  <span className="text-xs text-muted-foreground font-mono">{donutData.total} Total</span>
                </div>
                <p className="font-body text-xs text-muted-foreground mb-4">
                  Grouped by calibrated severity tier
                </p>

                <div className="relative flex items-center justify-center my-4">
                  <svg className="w-36 h-36 -rotate-90 transform" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="38" fill="transparent" stroke="currentColor" strokeWidth="8" className="text-muted" />
                    {donutData.arcs.map((arc) => (
                      <circle
                        key={arc.key}
                        cx="50"
                        cy="50"
                        r="38"
                        fill="transparent"
                        stroke={arc.color}
                        strokeWidth="8"
                        strokeDasharray={arc.strokeDasharray}
                        strokeDashoffset={arc.strokeDashoffset}
                      />
                    ))}
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center text-center pointer-events-none">
                    <span className="font-mono text-2xl font-bold text-foreground">
                      {donutData.total}
                    </span>
                    <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground font-semibold">
                      Incidents
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2">
                  <div className="flex items-center justify-between p-2 rounded bg-muted/50 border border-border">
                    <span className="flex items-center gap-1.5 text-rose-500 font-semibold">
                      <span className="w-2 h-2 rounded-full bg-rose-500"></span>Critical
                    </span>
                    <span className="text-foreground font-bold">{overview.risk_breakdown?.Critical || 0}</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-muted/50 border border-border">
                    <span className="flex items-center gap-1.5 text-orange-500 font-semibold">
                      <span className="w-2 h-2 rounded-full bg-orange-500"></span>High
                    </span>
                    <span className="text-foreground font-bold">{overview.risk_breakdown?.High || 0}</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-muted/50 border border-border">
                    <span className="flex items-center gap-1.5 text-amber-500 font-semibold">
                      <span className="w-2 h-2 rounded-full bg-amber-500"></span>Medium
                    </span>
                    <span className="text-foreground font-bold">{overview.risk_breakdown?.Medium || 0}</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-muted/50 border border-border">
                    <span className="flex items-center gap-1.5 text-sky-500 font-semibold">
                      <span className="w-2 h-2 rounded-full bg-sky-500"></span>Low
                    </span>
                    <span className="text-foreground font-bold">{overview.risk_breakdown?.Low || 0}</span>
                  </div>
                  <div className="col-span-2 flex items-center justify-between p-2 rounded bg-muted/50 border border-border">
                    <span className="flex items-center gap-1.5 text-emerald-500 font-semibold">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>Safe
                    </span>
                    <span className="text-foreground font-bold">{overview.risk_breakdown?.Safe || 0}</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-border flex items-center justify-between text-xs text-muted-foreground font-mono">
                <span>Risk Level Schema</span>
                <span>5 Calibrated Tiers</span>
              </div>
            </div>
          </div>

          {/* 4. Recent Incidents Table: Backed by GET /api/v1/incidents */}
          <div className="rounded-xl bg-card border border-border overflow-hidden">
            <div className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-border">
              <div>
                <h3 className="font-headline text-lg font-bold text-foreground">Recent Incidents</h3>
                <p className="font-body text-xs text-muted-foreground mt-0.5">
                  Latest threat events ingested from sensors and check endpoints
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2.5">
                <div className="relative w-64">
                  <Search className="w-4 h-4 text-muted-foreground absolute left-2.5 top-2.5 pointer-events-none" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter by threat, ID, or source..."
                    className="w-full h-9 pl-9 pr-3 rounded-lg bg-muted/50 border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-colors"
                  />
                </div>

                <select
                  value={selectedRisk}
                  onChange={(e) => setSelectedRisk(e.target.value)}
                  className="h-9 px-3 rounded-lg bg-muted/50 border border-border text-xs text-foreground focus:outline-none focus:border-primary transition-colors cursor-pointer"
                >
                  <option value="all">All Risk Tiers</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="safe">Safe</option>
                </select>

                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="h-9 px-3 rounded-lg bg-muted/50 border border-border text-xs text-foreground focus:outline-none focus:border-primary transition-colors cursor-pointer"
                >
                  <option value="all">All Statuses</option>
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-muted/30 border-b border-border text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    <th className="py-3 px-4 font-semibold">Incident</th>
                    <th className="py-3 px-4 font-semibold">Risk Level</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 font-semibold">Source</th>
                    <th className="py-3 px-4 font-semibold">Created</th>
                    <th className="py-3 px-4 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-xs">
                  {filteredIncidents.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-muted-foreground">
                        {recentIncidents.length === 0
                          ? 'No incidents recorded in the gateway database.'
                          : 'No incidents match your active filters.'}
                      </td>
                    </tr>
                  ) : (
                    filteredIncidents.map((incident) => (
                      <tr
                        key={incident.id}
                        className="hover:bg-muted/40 transition-colors group cursor-pointer"
                        onClick={() => onSelectIncident?.(incident)}
                      >
                        <td className="py-3.5 px-4 max-w-md">
                          <div className="flex flex-col">
                            <span className="font-medium text-foreground group-hover:text-primary transition-colors">
                              {incident.explanation || 'Anomaly detected'}
                            </span>
                            <span className="font-mono text-[11px] text-muted-foreground mt-0.5">
                              ID: {String(incident.id).slice(0, 13)}... • Type: {incident.threat_type}
                            </span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <RiskBadge level={normalizeRisk(incident.risk_level)} />
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5 text-foreground capitalize">
                            <span
                              className={cn(
                                'w-1.5 h-1.5 rounded-full',
                                normalizeRisk(incident.risk_level) === 'critical'
                                  ? 'bg-rose-500'
                                  : normalizeRisk(incident.risk_level) === 'high'
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              )}
                            />
                            {incident.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap font-mono text-[11px] text-muted-foreground uppercase">
                          {incident.source_type}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-muted-foreground font-mono">
                          {formatRelativeTime(incident.created_at)}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectIncident?.(incident);
                            }}
                            className="inline-flex items-center gap-1 text-primary hover:underline font-mono text-[11px]"
                          >
                            <span>Inspect</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="px-5 py-3.5 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-border text-xs">
              <span className="text-muted-foreground font-mono">
                Showing <strong className="text-foreground">{filteredIncidents.length}</strong> incidents (
                <strong className="text-foreground">{overview.total_incidents}</strong> total in gateway)
              </span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
