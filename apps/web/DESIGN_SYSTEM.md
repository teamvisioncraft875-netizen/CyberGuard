# CyberGuard Design System Specification

## 1. Executive Summary & Architecture

The CyberGuard Web Design System has been migrated from a dark-only TypeScript custom implementation to an enterprise-grade **JavaScript + shadcn/ui** design system supporting seamless **Light & Dark dual-theming**.

### Core Architecture Principles
- **Primitives**: Standard [Radix UI](https://www.radix-ui.com/) primitives managed through shadcn/ui conventions.
- **Styling**: Tailwind CSS v3 with CSS variable-backed HSL tokens defined in `src/index.css` and mapped in `tailwind.config.js`.
- **Variant Management**: `class-variance-authority` (CVA) combined with `clsx` and `tailwind-merge` via `src/utils/cn.js`.
- **Runtime**: Pure JavaScript (ESM / JSX) — 100% free of TypeScript compiler dependencies, with descriptive JSDoc type annotations on critical data contracts.
- **Visual Continuity**: 0 px layout shift when toggling themes; padding, border-radii, font weights, and spacing tokens remain identical across themes.

---

## 2. Dual-Theming System (Light & Dark)

The theme engine supports automatic OS preference detection, explicit user toggling, and persistent state across reloads.

### Theming Behavior & Defaults
1. **Default Theme**: On initial load (no saved localStorage key and no OS signal), defaults to **Dark Mode** (`dark`), preserving CyberGuard's approved Obsidian Sentinel aesthetic.
2. **OS Fallback**: If no preference is stored in localStorage, evaluates `window.matchMedia('(prefers-color-scheme: ...)')`.
3. **Storage Persistence**: Saved under `localStorage` key `'cyberguard-theme'` with values `'light' | 'dark'`.
4. **DOM Synchronization**: Dynamically toggles the `.dark` class on the root `<html>` element.

### Theme Profiles

| Attribute | Light Theme (Enterprise SaaS) | Dark Theme (Enterprise SaaS Dark) |
| :--- | :--- | :--- |
| **Philosophy** | Stripe / Linear / Notion calm enterprise aesthetic | Linear / Vercel restrained enterprise dark mode |
| **Canvas (`--background`)** | `hsl(210 20% 98%)` (`#f8fafc` soft off-white) | `hsl(224 30% 8%)` (`#0f131c` void obsidian) |
| **Foreground (`--foreground`)** | `hsl(222 47% 11%)` (`#0f172a` slate-900) | `hsl(228 30% 90%)` (`#dfe2ee` crisp titanium) |
| **Primary Accent (`--primary`)** | `hsl(199 89% 44%)` (`#0284c7` restrained cyan-blue) | `hsl(217 70% 56%)` (`#4878d6` restrained indigo-blue) |
| **Primary Text (`--primary-foreground`)** | `hsl(0 0% 100%)` (pure white text) | `hsl(0 0% 100%)` (pure white text) |
| **Secondary (`--secondary`)** | `hsl(210 40% 96%)` (`#f1f5f9` subtle grey) | `hsl(220 14% 18%)` (`#262a33` muted neutral) |
| **Cards / Surfaces (`--card`)** | `hsl(0 0% 100%)` (`#ffffff` pure white) | `hsl(220 18% 14%)` (`#1c2028` container surface) |
| **Muted Grey (`--muted`)** | `hsl(210 40% 96%)` (`#f1f5f9` subtle grey) | `hsl(220 14% 18%)` (`#262a33` charcoal) |
| **Border (`--border`)** | `hsl(214 32% 91%)` (`#e2e8f0` clean hairline) | `hsl(220 13% 20%)` (`#2b2f38` clean hairline) |
| **Destructive (`--destructive`)**| `hsl(351 85% 54%)` (`#e11d48` crimson) | `hsl(351 85% 54%)` (`#e11d48` solid red) |
| **Focus Ring (`--ring`)** | `hsl(199 89% 44%)` | `hsl(217 70% 56%)` |

### CSS Variables Token Reference (`src/index.css`)

```css
:root {
  --background: 210 20% 98%;
  --foreground: 222 47% 11%;
  --card: 0 0% 100%;
  --card-foreground: 222 47% 11%;
  --popover: 0 0% 100%;
  --popover-foreground: 222 47% 11%;
  --primary: 199 89% 44%;
  --primary-foreground: 0 0% 100%;
  --secondary: 210 40% 96%;
  --secondary-foreground: 222 47% 11%;
  --muted: 210 40% 96%;
  --muted-foreground: 215 16% 47%;
  --accent: 210 40% 94%;
  --accent-foreground: 222 47% 11%;
  --destructive: 351 85% 54%;
  --destructive-foreground: 0 0% 100%;
  --border: 214 32% 91%;
  --input: 214 32% 91%;
  --ring: 199 89% 44%;
  --focus-ring: 199 89% 44%;
  --surface: 0 0% 100%;
  --surface-elevated: 0 0% 100%;
  --surface-lowest: 0 0% 100%;
  --surface-low: 210 20% 98%;
  --surface-container: 0 0% 100%;
  --surface-high: 210 40% 96%;
  --surface-highest: 214 32% 91%;
}

.dark {
  --background: 224 30% 8%;
  --foreground: 228 30% 90%;
  --card: 220 18% 14%;
  --card-foreground: 228 30% 90%;
  --popover: 220 20% 12%;
  --popover-foreground: 228 30% 90%;
  --primary: 217 70% 56%;
  --primary-foreground: 0 0% 100%;
  --secondary: 220 14% 18%;
  --secondary-foreground: 228 30% 90%;
  --muted: 220 14% 18%;
  --muted-foreground: 215 16% 55%;
  --accent: 220 14% 18%;
  --accent-foreground: 228 30% 90%;
  --destructive: 351 85% 54%;
  --destructive-foreground: 0 0% 100%;
  --border: 220 13% 20%;
  --input: 220 13% 20%;
  --ring: 217 70% 56%;
  --focus-ring: 217 70% 56%;
  --surface: 220 18% 14%;
  --surface-elevated: 220 20% 16%;
  --surface-lowest: 220 38% 6%;
  --surface-low: 220 20% 12%;
  --surface-container: 220 18% 14%;
  --surface-high: 222 14% 18%;
  --surface-highest: 223 11% 22%;
}
```

### How to Use `useTheme()` & `ThemeToggle`

```jsx
import { useTheme } from '@/hooks/useTheme';
import { ThemeToggle } from '@/components/ui';

function ExampleComponent() {
  const { theme, setTheme, toggleTheme } = useTheme();

  return (
    <div>
      <span>Active theme: {theme}</span>
      <button onClick={toggleTheme}>Toggle</button>
      <ThemeToggle variant="outline" size="sm" />
    </div>
  );
}
```

---

## 3. Calibrated 5-Tier Threat Risk Colors

CyberGuard enforces strict semantic threat encoding across all incident feeds, telemetry badges, and scan outputs. The meaning of colors **never shifts** between themes; only contrast, saturation, and luminance are adjusted to ensure WCAG AAA accessibility.

| Risk Tier | Score Range | Meaning | Light Mode Encodings | Dark Mode Encodings |
| :--- | :---: | :--- | :--- | :--- |
| **Safe** | 0 – 19 | Verified benign origin | `bg-emerald-50 text-emerald-700 border-emerald-300` | `bg-emerald-950/40 text-emerald-400 border-emerald-800/40` |
| **Low** | 20 – 39 | Minor anomaly / informational | `bg-sky-50 text-sky-700 border-sky-300` | `bg-sky-950/40 text-sky-400 border-sky-800/40` |
| **Medium** | 40 – 69 | Suspicious lexical/behavioral cues | `bg-amber-50 text-amber-700 border-amber-300` | `bg-amber-950/40 text-amber-400 border-amber-800/40` |
| **High** | 70 – 89 | Strong threat indicators | `bg-orange-50 text-orange-700 border-orange-300` | `bg-orange-950/40 text-orange-400 border-orange-800/40` |
| **Critical** | 90 – 100 | Confirmed attack / urgent exploit | `bg-rose-50 text-rose-700 border-rose-300` | `bg-rose-950/50 text-rose-400 border-rose-800/50` |

> [!IMPORTANT]
> **Static Threat Badges & Strict Anti-Glow Policy**: Critical risk badges (and all other risk tiers) are strictly static, solid, high-contrast badges with zero `animate-pulse`, zero `animate-ping`, and zero box-shadow/glow effects across both themes. Neon cyberpunk accents (`#00f0ff`) are strictly banned; enterprise restrained indigo-blue (`hsl(217 70% 56%)`) and neutral slate secondary surfaces are enforced.

### Risk Utilities (`src/utils/risk.js`)
- `normalizeRisk(input)`: Converts any raw string or alias (`'p0'`, `'crit'`, `'warn'`, `'clean'`) into canonical `'safe' | 'low' | 'medium' | 'high' | 'critical'`.
- `riskFromScore(score)`: Converts numeric score [0..100] to corresponding 5-tier level.
- `compareRisk(a, b)`: Comparator for sorting incidents by descending severity.
- `getRiskConfig(level)`: Returns complete dual-theme classnames, score ranges, and descriptions.

---

## 4. Component Catalog & Props API

### 1. `Button` (`src/components/ui/Button.jsx`)
- **Source**: shadcn/ui Button extended with CVA and CyberGuard helper props.
- **Props**:
  - `variant`: `'default'` | `'primary'` | `'destructive'` | `'danger'` | `'outline'` | `'secondary'` | `'ghost'` | `'link'` | `'warning'` | `'success'`
  - `size`: `'default'` | `'md'` | `'sm'` | `'lg'` | `'icon'`
  - `isLoading`: `boolean` (displays spinning `Loader2` and disables pointer events)
  - `disabled`: `boolean`
  - `icon` / `iconLeft`: React icon component or node (rendered left of label)
  - `iconRight`: React icon component or node (rendered right of label)
  - `asChild`: `boolean` (delegates rendering to Radix `Slot`)

### 2. `Input` (`src/components/ui/Input.jsx`)
- **Source**: shadcn/ui Input with CyberGuard SOC extensions.
- **Props**:
  - `type`: standard HTML input types (`'text'`, `'password'`, `'email'`, etc.)
  - `label`: optional uppercase label rendered above input
  - `error`: error string (displays warning alert and highlights border in `destructive`)
  - `helperText`: contextual hint text
  - `iconLeft`: icon rendered inside left padding
  - `iconRight`: icon rendered inside right padding
  - `onClear`: callback to render quick "x" clear button when input has value
  - `containerClassName`: class overrides on outer wrapper

### 3. `Badge` (`src/components/ui/Badge.jsx`)
- **Source**: shadcn/ui Badge.
- **Props**:
  - `variant`: `'default'` | `'secondary'` | `'destructive'` | `'danger'` | `'outline'` | `'accent'` | `'success'` | `'warning'` | `'muted'`
  - `size`: `'sm'` | `'md'` | `'lg'`

### 4. `RiskBadge` (`src/components/ui/RiskBadge.jsx`)
- **Source**: Custom CyberGuard wrapper around shadcn/ui `Badge`.
- **Props**:
  - `level`: raw threat string (e.g., `'critical'`, `'p0'`, `'high'`, `'warn'`, `'safe'`)
  - `score`: optional numeric score [0..100] rendered in monospace badge suffix
  - `size`: `'sm'` | `'md'` | `'lg'`
  - `showDot`: `boolean` (renders calibrated pulse status indicator)
  - `showIcon`: `boolean` (renders Lucide security icon for level)

### 5. `Card` (`src/components/ui/Card.jsx`)
- **Source**: shadcn/ui Card primitives (`Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`, `CardFooter`).
- **Extensions**:
  - `variant="interactive"`: adds hover border and cursor pointer
  - `hoverEffect`: adds subtle `-translate-y-0.5` transform
  - `glow`: adds laser cyan outer glow

### 6. `Table` (`src/components/ui/Table.jsx`)
- **Source**: shadcn/ui Table primitives (`Table`, `TableHeader`, `TableBody`, `TableFooter`, `TableRow`, `TableHead`, `TableCell`, `TableCaption`).
- **Styling**: Automatically adapts hover row highlighting and zebra styling across light and dark backgrounds.

### 7. `Modal` (`src/components/ui/Modal.jsx`) & `Dialog` (`src/components/ui/Dialog.jsx`)
- **Source**: shadcn/ui Dialog with Radix UI modal backdrop and focus trapping.
- **Props**:
  - `isOpen`: `boolean`
  - `onClose`: function
  - `title`: modal header title
  - `description`: modal subheader description
  - `size`: `'sm'` | `'md'` | `'lg'` | `'xl'` | `'full'`
  - `children`: modal body content

### 8. `Drawer` (`src/components/ui/Drawer.jsx`) & `Sheet` (`src/components/ui/Sheet.jsx`)
- **Source**: shadcn/ui Sheet primitives (`Sheet`, `SheetContent`, `SheetHeader`, `SheetTitle`, `SheetDescription`, `SheetFooter`).
- **Props**:
  - `isOpen`: `boolean`
  - `onClose`: function
  - `title`: header title
  - `subtitle`: optional description
  - `position`: `'left'` | `'right'`
  - `size`: `'md'` | `'lg'` | `'xl'` | `'2xl'` | `'full'`
  - `width`: optional custom CSS width class (e.g. `'w-full max-w-xl'`)
  - `footer`: custom footer action node
  - `children`: drawer body content

### 9. `Loader` (`src/components/ui/Loader.jsx`) & `Skeleton` (`src/components/ui/Skeleton.jsx`)
- **Source**: shadcn/ui Skeleton + Loader spinner component.
- **Props**:
  - `variant`: `'spinner'` | `'skeleton'`
  - `size`: `'sm'` | `'md'` | `'lg'` | `'xl'`
  - `text`: optional uppercase status message
  - `fullPage`: renders full-screen backdrop overlay

### 10. `EmptyState` (`src/components/ui/EmptyState.jsx`)
- **Source**: Custom component built using shadcn/ui `Card` and `Button` primitives.
- **Props**:
  - `icon`: React icon component
  - `title`: headline message
  - `description`: detailed explanation
  - `actionLabel`: button label
  - `onAction`: button click handler
  - `action`: custom action element
  - `children`: optional extra content

### 11. `AlertToast` & `useToast()` (`src/hooks/useToast.jsx`, `src/components/ui/Sonner.jsx`)
- **Source**: shadcn/ui Sonner integration with ToastProvider context wrapper.
- **API**:
  - `toast.success(message, options)`
  - `toast.error(message, options)`
  - `toast.warning(message, options)`
  - `toast.info(message, options)`
  - `toast.critical(message, options)`
  - `toast.show({ type, title, message })`
  - `useToast().addToast({ type, title, message })`

---

## 5. Layouts & Routed Page Shells

| Layout / Page | Route / ID | Description |
| :--- | :--- | :--- |
| `AppLayout` | Persistent shell | Global SOC topbar with live search, node status indicators, and **ThemeToggle**; fixed collapsible sidebar navigation. |
| `AuthLayout` | Auth shell | Centered cryptographic card shell with ambient glows and top-right **ThemeToggle**. |
| `DashboardPage` | `'dashboard'` | Real-time threat radar, MITRE ATT&CK kill-chain timeline, and incident triage table. |
| `ScanCenterPage` | `'scan-center'` | Deepfake audio waveform analyzer, ViT steganography scanner, and QR/URL verification center. |
| `IncidentsPage` | `'incidents'` | Full incident inventory with search, severity filtering, and containment actions. |
| `GuardianPage` | `'guardian'` | Real-time eBPF pod protection and guardian mode link monitor. |
| `SettingsPage` | `'settings'` | Microservice health monitors (Gateway, ML Service, PG, Socket.io) and policy sliders. |
| `LoginPage` | `'login'` | SOC Analyst gateway authentication with credentials and optional MFA token input. |
| `SignupPage` | `'signup'` | SOC operator provisioning form with cryptographic compliance confirmation. |
| `DesignSystemPage` | `'design-system'` | Live visual showcase of all components with interactive **ThemeToggle** at the top. |
| `AppRoutes` | Routing router | Declarative router component mapping all route IDs to their page views. |

---

## 6. Verification & Build Integrity

- **TypeScript Removal**: 100% of source files converted to `.jsx` and `.js`. `tsconfig.json` removed.
- **Production Build**: Verified with `npm run build` — compiles clean in ~1s with 0 errors.
- **Dual-Theme Verification**: Tested via `/design-system` in both Light (Stripe/Linear/Notion) and Dark (Obsidian Sentinel) modes.
