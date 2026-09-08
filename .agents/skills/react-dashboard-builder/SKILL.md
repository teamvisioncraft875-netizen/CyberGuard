---
name: react-dashboard-builder
description: Builds the React Command Dashboard, real-time incident feeds, Recharts analytics, and shadcn/ui security interfaces for CYBERGUARD. Activate when developing apps/web, creating incident triage tables, implementing threat timelines, connecting WebSocket listeners, or styling security components with Tailwind CSS.
---

# React Dashboard Builder — Command Dashboard

This skill guides the construction of the **Web Command Dashboard** (`apps/web/`), the primary operational interface for individual users and enterprise SOC analysts.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Design Principles for Security UX
- **Calm and Precise Under Pressure:** A security operations dashboard must never look chaotic, flashy, or cartoonish. Use dark-mode-first aesthetic with disciplined accent colors.
- **Color Palette Conventions:**
  - `Safe`: Emerald (`#10B981` / `text-emerald-400`)
  - `Low`: Blue / Sky (`#0EA5E9` / `text-sky-400`)
  - `Medium`: Amber / Yellow (`#F59E0B` / `text-amber-400`)
  - `High`: Orange / Coral (`#F97316` / `text-orange-400`)
  - `Critical`: Rose / Red (`#EF4444` / `text-rose-500`)
- **Restrained Animation:** Use `framer-motion` only for subtle fade-ins when new incidents appear or when switching views. Avoid bouncy or playful animations.

---

## 2. Component Hierarchy & Architecture (`apps/web/src/`)

```
apps/web/src/
├── components/
│   ├── ui/               # Primitive shadcn/ui components (Button, Dialog, Table, Badge)
│   ├── shared/           # RiskBadge, ThreatScoreGauge, MitreTag, UserAvatar
│   ├── dashboard/        # MetricsSummaryCards, LiveIncidentFeed, ThreatTimelineChart
│   └── incident-detail/  # IncidentModal, SignalInspector, RemediationActions
├── hooks/                # useIncidents, useIncidentSocket, useAuth
├── services/             # Axios API client instances and endpoint callers
├── types/                # TypeScript definitions matching docs/API_CONTRACT.md
└── pages/                # OverviewPage, IncidentInvestigationPage, SettingsPage
```

---

## 3. Key Component Implementations

### Risk Badge Component (`components/shared/RiskBadge.tsx`)
```tsx
import React from 'react';
import { Badge } from '@/components/ui/badge';

export type RiskLevel = 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';

const riskConfig: Record<RiskLevel, { label: string; className: string }> = {
  Safe: { label: 'Safe', className: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
  Low: { label: 'Low', className: 'bg-sky-500/10 text-sky-400 border-sky-500/30' },
  Medium: { label: 'Medium', className: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  High: { label: 'High', className: 'bg-orange-500/10 text-orange-400 border-orange-500/30' },
  Critical: { label: 'Critical', className: 'bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse' },
};

export const RiskBadge: React.FC<{ level: RiskLevel }> = ({ level }) => {
  const config = riskConfig[level] || riskConfig.Low;
  return (
    <Badge variant="outline" className={`font-mono font-medium px-2 py-0.5 ${config.className}`}>
      {config.label}
    </Badge>
  );
};
```

### Real-Time Live Incident Item (`components/dashboard/IncidentRow.tsx`)
```tsx
import React from 'react';
import { motion } from 'framer-motion';
import { RiskBadge, RiskLevel } from '@/components/shared/RiskBadge';

interface IncidentRowProps {
  id: string;
  threatScenario: string;
  riskTier: RiskLevel;
  explanation: string;
  timestamp: string;
  onSelect: (id: string) => void;
}

export const IncidentRow: React.FC<IncidentRowProps> = ({
  id, threatScenario, riskTier, explanation, timestamp, onSelect
}) => (
  <motion.tr
    initial={{ opacity: 0, y: -8 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.2 }}
    onClick={() => onSelect(id)}
    className="border-b border-zinc-800 hover:bg-zinc-900/60 cursor-pointer transition-colors"
  >
    <td className="py-3 px-4 text-xs font-mono text-zinc-400">{timestamp}</td>
    <td className="py-3 px-4 font-semibold text-zinc-200">{threatScenario}</td>
    <td className="py-3 px-4"><RiskBadge level={riskTier} /></td>
    <td className="py-3 px-4 text-sm text-zinc-400 truncate max-w-md">{explanation}</td>
  </motion.tr>
);
```

---

## 4. Frontend Standards Checklist
- [ ] No inline styling objects (`style={{ ... }}`). Use Tailwind CSS exclusively.
- [ ] UI elements built from modular primitives in `components/ui/` (`shadcn/ui`).
- [ ] Connects to real-time events via `useIncidentSocket` hook.
- [ ] Visual charts use `Recharts` (`ResponsiveContainer`, `LineChart`, `BarChart`).
- [ ] Shows `"Analysing..."` skeleton loaders while async ML models evaluate payloads.
