import React, { useState } from 'react';
import {
  Button,
  Input,
  Badge,
  RiskBadge,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
  Modal,
  Drawer,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
  Skeleton,
  Loader,
  EmptyState,
  Alert,
  ThemeToggle,
} from '../components/ui';
import { useModal } from '../hooks/useModal';
import { useToast } from '../hooks/useToast';
import { useTheme } from '../hooks/useTheme';
import {
  ShieldAlert,
  Search,
  Lock,
  Mail,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Terminal,
  RefreshCw,
  Cpu,
  Sun,
  Moon,
  Zap,
} from 'lucide-react';

export function DesignSystemPage() {
  const toast = useToast();
  const { theme, toggleTheme } = useTheme();
  const sampleModal = useModal(false);
  const sampleDrawer = useModal(false);

  // Input states
  const [searchValue, setSearchValue] = useState('');
  const [passwordValue, setPasswordValue] = useState('');
  const [errorInputValue, setErrorInputValue] = useState('suspicious_payload.exe');
  const [btnLoading, setBtnLoading] = useState(false);

  // Table sample data
  const sampleIncidents = [
    {
      id: 'INC-8491',
      threat: 'Urgent Wire Transfer Phishing',
      type: 'phishing',
      risk: 'critical',
      score: 96,
      source: 'email',
      time: '2 mins ago',
      status: 'open',
    },
    {
      id: 'INC-8490',
      threat: 'Synthetic Audio Impersonation',
      type: 'deepfake',
      risk: 'high',
      score: 84,
      source: 'audio',
      time: '14 mins ago',
      status: 'investigating',
    },
    {
      id: 'INC-8489',
      threat: 'Abnormal Outbound Network Spike',
      type: 'technical_threat',
      risk: 'medium',
      score: 58,
      source: 'system',
      time: '1 hour ago',
      status: 'open',
    },
    {
      id: 'INC-8488',
      threat: 'Lookalike Banking Domain',
      type: 'malicious_url',
      risk: 'low',
      score: 32,
      source: 'url',
      time: '3 hours ago',
      status: 'resolved',
    },
    {
      id: 'INC-8487',
      threat: 'Verified Internal Password Reset',
      type: 'account_takeover',
      risk: 'safe',
      score: 8,
      source: 'login',
      time: '5 hours ago',
      status: 'resolved',
    },
  ];

  const handleTestLoading = () => {
    setBtnLoading(true);
    setTimeout(() => {
      setBtnLoading(false);
      toast.success('Simulated asynchronous action completed.');
    }, 1500);
  };

  return (
    <div className="space-y-12 max-w-6xl mx-auto pb-16 font-sans">
      {/* Top Banner & Theme Switcher Controller */}
      <div className="border-b border-border pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">
              SHADCN/UI + JS DESIGN SYSTEM
            </span>
            <span className="text-xs font-mono text-muted-foreground uppercase">
              Light & Dark Dual-Themed
            </span>
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-foreground font-headline">
            CyberGuard Design System Showcase
          </h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl leading-relaxed">
            Standard shadcn/ui components wired with Radix UI, CVA, tailwind-merge, and calibrated 5-tier threat tokens.
          </p>
        </div>

        {/* Theme Switcher Header Widget */}
        <div className="flex items-center gap-3 p-3 rounded-xl bg-card border border-border shadow-sm">
          <div className="flex flex-col text-right">
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              Current Active Theme
            </span>
            <span className="text-xs font-mono font-bold capitalize text-primary">
              {theme} Mode
            </span>
          </div>
          <ThemeToggle variant="outline" size="md" />
        </div>
      </div>

      {/* 1. RISK BADGES (Calibrated 5 Tiers) */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            1. Calibrated Threat Risk Badges
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Wrapper around shadcn/ui Badge using normalizeRisk(). Automatically switches styling in Light vs Dark mode.
          </p>
        </div>

        <Card className="p-6">
          <div className="space-y-6">
            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
                Standard Tiers with Status Dot & Score
              </span>
              <div className="flex flex-wrap items-center gap-3">
                <RiskBadge level="safe" score={12} size="lg" />
                <RiskBadge level="low" score={28} size="lg" />
                <RiskBadge level="medium" score={62} size="lg" />
                <RiskBadge level="high" score={85} size="lg" />
                <RiskBadge level="critical" score={98} size="lg" />
              </div>
            </div>

            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
                With Threat Category Icons
              </span>
              <div className="flex flex-wrap items-center gap-3">
                <RiskBadge level="safe" showIcon />
                <RiskBadge level="low" showIcon />
                <RiskBadge level="medium" showIcon />
                <RiskBadge level="high" showIcon />
                <RiskBadge level="critical" showIcon />
              </div>
            </div>

            <div>
              <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
                String Normalization Demonstration (Handles any casing/input)
              </span>
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <div className="flex items-center gap-1.5 p-2 rounded bg-muted">
                  <span className="text-muted-foreground">Input: "p0"</span>
                  <RiskBadge level="p0" size="sm" />
                </div>
                <div className="flex items-center gap-1.5 p-2 rounded bg-muted">
                  <span className="text-muted-foreground">Input: "WARNING"</span>
                  <RiskBadge level="WARNING" size="sm" />
                </div>
                <div className="flex items-center gap-1.5 p-2 rounded bg-muted">
                  <span className="text-muted-foreground">Input: "Verified Benign"</span>
                  <RiskBadge level="Verified Benign" size="sm" />
                </div>
              </div>
            </div>
          </div>
        </Card>
      </section>

      {/* 2. BUTTONS */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            2. Shadcn/ui Buttons
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            CVA button variants supporting loading states, icons, and sizes.
          </p>
        </div>

        <Card className="p-6 space-y-6">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
              Variants
            </span>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="default">Default / Primary</Button>
              <Button variant="secondary">Secondary</Button>
              <Button variant="outline">Outline</Button>
              <Button variant="ghost">Ghost</Button>
              <Button variant="destructive">Destructive / Danger</Button>
              <Button variant="warning">Warning</Button>
              <Button variant="success">Success</Button>
            </div>
          </div>

          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
              With Icons & Loading State
            </span>
            <div className="flex flex-wrap items-center gap-3">
              <Button iconLeft={Mail}>Send Notification</Button>
              <Button variant="outline" iconRight={ExternalLink}>Open Portal</Button>
              <Button
                variant="default"
                isLoading={btnLoading}
                onClick={handleTestLoading}
              >
                {btnLoading ? 'Detonating...' : 'Trigger Detonation'}
              </Button>
            </div>
          </div>
        </Card>
      </section>

      {/* 3. INPUTS */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            3. Shadcn/ui Inputs
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Accessible input fields with icons, password peek toggle, and validation errors.
          </p>
        </div>

        <Card className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Input
              label="Asset or Domain Search"
              placeholder="e.g. login.0kta-verify-portal.net"
              iconLeft={Search}
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onClear={() => setSearchValue('')}
              helperText="Press ⌘K to open global search index"
            />

            <Input
              type="password"
              label="API Secret Token"
              placeholder="Enter master encryption key..."
              iconLeft={Lock}
              value={passwordValue}
              onChange={(e) => setPasswordValue(e.target.value)}
            />

            <Input
              label="Quarantined Payload Name"
              value={errorInputValue}
              onChange={(e) => setErrorInputValue(e.target.value)}
              error="Payload flagged with Trojan.Generic signature"
            />
          </div>
        </Card>
      </section>

      {/* 4. CARDS */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            4. Shadcn/ui Cards
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Composable Card, CardHeader, CardTitle, CardDescription, CardContent, and CardFooter.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Standard Card</CardTitle>
              <CardDescription>Default surface elevation</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Built with standard CSS variables for seamless light/dark mode adaptation.
              </p>
            </CardContent>
            <CardFooter>
              <Button variant="outline" size="sm">Inspect</Button>
            </CardFooter>
          </Card>

          <Card variant="interactive">
            <CardHeader>
              <CardTitle>Interactive Hover Card</CardTitle>
              <CardDescription>Responds to analyst focus</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Subtle border transition on hover and focus.
              </p>
            </CardContent>
            <CardFooter>
              <Badge variant="secondary">Interactive</Badge>
            </CardFooter>
          </Card>

          <Card className="border-primary/50">
            <CardHeader>
              <CardTitle className="text-primary flex items-center justify-between">
                <span>Active Threat Node</span>
                <Flame className="w-4 h-4 text-destructive" />
              </CardTitle>
              <CardDescription>Air-gap protocol engaged</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Perimeter border highlight for critical tactical widgets.
              </p>
            </CardContent>
            <CardFooter>
              <RiskBadge level="critical" />
            </CardFooter>
          </Card>
        </div>
      </section>

      {/* 5. TABLE */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            5. Shadcn/ui Table
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Dense, high-efficiency data grid with sticky headers and risk badges.
          </p>
        </div>

        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Incident</TableHead>
                <TableHead>Vector</TableHead>
                <TableHead>Risk Level</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sampleIncidents.map((inc) => (
                <TableRow key={inc.id} className="cursor-pointer">
                  <TableCell>
                    <div className="font-semibold text-foreground">{inc.threat}</div>
                    <div className="text-[11px] font-mono text-muted-foreground">{inc.id}</div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{inc.type}</TableCell>
                  <TableCell>
                    <RiskBadge level={inc.risk} score={inc.score} size="sm" />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{inc.status}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{inc.time}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm">Details</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      </section>

      {/* 6. MODALS & DRAWERS (Dialog & Sheet) */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            6. Dialog (Modal) & Sheet (Drawer)
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Radix UI Dialog and Sheet overlays.
          </p>
        </div>

        <Card className="p-6">
          <div className="flex flex-wrap items-center gap-4">
            <Button variant="default" onClick={sampleModal.open}>
              Open Dialog (Modal)
            </Button>
            <Button variant="outline" onClick={sampleDrawer.open}>
              Open Sheet (Drawer)
            </Button>
          </div>
        </Card>

        {/* Modal Instance */}
        <Modal
          isOpen={sampleModal.isOpen}
          onClose={sampleModal.close}
          title="Air-Gap Host Confirmation"
          description="Are you sure you want to isolate cluster node k8s-node-prod-04?"
        >
          <div className="space-y-4">
            <Alert type="warning" title="Irreversible Action">
              Isolating this node will drop all active WebSocket streams and terminate inbound HTTP ingress.
            </Alert>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={sampleModal.close}>Cancel</Button>
              <Button
                variant="destructive"
                onClick={() => {
                  sampleModal.close();
                  toast.critical('Host k8s-node-prod-04 successfully isolated.');
                }}
              >
                Confirm Isolation
              </Button>
            </div>
          </div>
        </Modal>

        {/* Drawer Instance */}
        <Drawer
          isOpen={sampleDrawer.isOpen}
          onClose={sampleDrawer.close}
          title="Forensic Deep Dive"
          subtitle="Detailed telemetry breakdown for INC-8491"
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 rounded-lg bg-muted border border-border">
              <span className="text-[10px] text-muted-foreground uppercase block">Host IP</span>
              <span className="text-foreground font-semibold">185.220.101.5 (Tor Exit Node)</span>
            </div>
            <div className="p-3 rounded-lg bg-muted border border-border">
              <span className="text-[10px] text-muted-foreground uppercase block">MITRE Tactic</span>
              <span className="text-primary font-semibold">T1566.002 Spearphishing Link</span>
            </div>
          </div>
        </Drawer>
      </section>

      {/* 7. TOASTS & ALERTS */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            7. Alerts & Toast Notifications
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Inline alert banners and floating Sonner toast notifications across all 5 risk priorities.
          </p>
        </div>

        <div className="space-y-4">
          <Alert type="info" title="System Nominal">
            Autonomous threat detection models synchronized with cloud telemetry.
          </Alert>
          <Alert type="success" title="Policy Enforced">
            SSL certificate auto-rotation completed successfully.
          </Alert>
          <Alert type="warning" title="Elevated Dwell Time">
            Dwell time on node-04 has exceeded 3.8 minutes.
          </Alert>
          <Alert type="critical" title="P0 Critical Incident">
            Credential harvest kit detected targeting executive accounts.
          </Alert>

          <Card className="p-6">
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-3 block">
              Test Sonner Toast Notifications
            </span>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => toast.success('Operation completed successfully.')}
              >
                toast.success
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => toast.info('New telemetry event ingested.')}
              >
                toast.info
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => toast.warning('High network egress detected.')}
              >
                toast.warning
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => toast.error('Connection dropped to API Gateway.')}
              >
                toast.error
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => toast.critical('P0: Immediate air-gap triggered!')}
              >
                toast.critical
              </Button>
            </div>
          </Card>
        </div>
      </section>

      {/* 8. EMPTY STATES & LOADERS */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-headline">
            8. Empty States & Skeletons
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Built using shadcn/ui Card, Button, and Skeleton primitives.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <EmptyState
            title="No Suspicious Payloads"
            description="Your transmission buffer is clear. Load a preset sample to begin deconstruction."
            actionLabel="Load Spear Phishing Sample"
            onAction={() => toast.info('Loaded sample EML payload')}
          />

          <Card className="p-6 space-y-4">
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground block">
              Skeleton Pulse Loaders
            </span>
            <div className="space-y-3">
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-5/6" />
              <div className="flex gap-2 pt-2">
                <Skeleton className="h-8 w-24 rounded-md" />
                <Skeleton className="h-8 w-20 rounded-md" />
              </div>
            </div>
          </Card>
        </div>
      </section>
    </div>
  );
}
