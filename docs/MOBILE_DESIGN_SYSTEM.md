# CYBERGUARD — Mobile & Web Enterprise Design System

**Minimal, Professional, Premium Enterprise-Grade UI/UX Specification**

---

## 1. Design Philosophy

CYBERGUARD is an enterprise and personal threat defense platform. The interface embodies the design ethos of high-trust enterprise platforms (such as 1Password, Apple Health, and Notion):
- **Minimalist**: Whitespace and dark space provide visual clarity. No distracting background gradients or decorative animations.
- **Intentional Color**: Colors serve functional purposes—indicating system health, threat levels, and interactive focus.
- **Typography-Led Hierarchy**: Clear font scale distinguishes high-severity threat signals from metadata.
- **Cross-Platform Reusability**: Components share identical props, state contracts, and theme tokens across React Web and React Native Mobile.

---

## 2. Color Palette & Tokens

### Primary Canvas & Surfaces
| Token | Dark Mode Hex | Light Mode Hex | Usage |
|---|---|---|---|
| `background` | `#0F0F0F` | `#F9FAFB` | Deepest canvas background |
| `card` | `#1A1A1A` | `#FFFFFF` | Primary card surfaces & modals |
| `surface` | `#242424` | `#F3F4F6` | Elevated surfaces, secondary inputs |
| `border` | `#2D2D2D` | `#E5E5E5` | Structural 1px dividers & borders |
| `borderActive` | `#00D9FF` | `#0088A3` | Active tab underlines & focused inputs |

### Typography Colors
| Token | Dark Mode Hex | Light Mode Hex | Usage |
|---|---|---|---|
| `textPrimary` | `#FFFFFF` | `#0F0F0F` | Headlines, screen titles, primary values |
| `textBody` | `#E5E5E5` | `#1F2937` | High-contrast readable body text |
| `textSecondary`| `#9CA3AF` | `#4B5563` | Subtitles, field labels, metadata |
| `textMuted` | `#6B7280` | `#6B7280` | Inactive states, timestamps, placeholders |
| `textInverse` | `#0F0F0F` | `#FFFFFF` | Text on inverted accent buttons |

### Functional Accents
| Token | Hex | Usage |
|---|---|---|
| `accent` | `#00D9FF` (Dark) / `#0088A3` (Light) | Primary actions, scan buttons, highlights |
| `success` | `#22C55E` | Confirmed safe, active telemetry, mitigated threats |
| `warning` | `#F59E0B` | Medium risk, warning alerts, elevating posture |
| `danger` | `#EF4444` | High risk, critical threats, report/block actions |
| `critical`| `#B91C1C` | Critical autonomous containment alerts |
| `neutral` | `#6B7280` | Unclassified indicators, disabled states |

---

## 3. Typography Hierarchy

| Style | Font Family | Size | Weight | Line Height | Usage |
|---|---|---|---|---|---|
| **H1** | Inter | 24pt | Bold (700) | 30px | Screen titles, key hero headers |
| **H2** | Inter | 20pt | Bold (700) | 26px | Navigation titles, console greeting |
| **H3** | Inter | 18pt | SemiBold (600) | 24px | Section titles, modal headers |
| **H4** | Inter | 16pt | SemiBold (600) | 22px | Card titles, scanner names |
| **Body Large** | Inter | 16pt | Regular (400) | 24px | Primary descriptions |
| **Body** | Inter | 14pt | Regular (400) | 20px | Standard content & findings |
| **Body Small** | Inter | 13pt | Regular (400) | 18px | Incident descriptions |
| **Label** | Inter | 12–13pt | SemiBold (600) | 16px | Buttons, badges, tab items |
| **Mono** | JetBrains Mono | 12pt | Regular (400) | 16px | IPs, SHA256 hashes, raw indicators |

---

## 4. Spacing & Grid System

- **Base Unit**: `8px`
- **Internal Card Padding**: `16px`
- **Internal Content Padding**: `12px`
- **Section Margins**: `16px` between major blocks
- **Element Margins**: `8px` between grid items
- **Border Radii**:
  - Cards: `8px`
  - Buttons: `4px` (strict enterprise square + minimal radius; no rounded pills)
  - Badges: `4px`
  - Toggles & Circular Buttons: `20px` (40x40px circle outline)
- **Tap Targets**: Minimum `44px` height on mobile for buttons and inputs.
- **Top Header**: Fixed `56px` height.

---

## 5. Global Component Library

### 1. `CyberLogo`
- **Specs**: 32x32px (mobile) / 40x40px (web).
- **Style**: Minimalist shield line art with cyan border + CYBERGUARD text.
- **Placement**: Top-left on all screens with 12px clear space.

### 2. `ThemeToggle`
- **Specs**: 40x40px circle outline button, 1px solid border, transparent fill.
- **Behavior**: Instantly toggles dark and light mode, storing preference in secure storage.
- **Icons**: Sun (`☼`) / Moon (`☾`).

### 3. `CopilotToggle` & `CopilotModal`
- **Specs**: 40x40px circle outline button with ⬡ symbol matching `ThemeToggle`.
- **Panel**: Side panel on Web / Modal on Mobile.
- **Chat UX**: 
  - User messages: Right-aligned, `#00D9FF` cyan fill with black text.
  - Copilot replies: Left-aligned, `#1A1A1A` card fill with 1px border.
  - Input field with 44px cyan `Send` button.

### 4. `AppHeader`
- **Specs**: 56px height, 1px bottom border.
- **Contents**: `CyberLogo` | [Flex Spacer] | `ThemeToggle` | `CopilotToggle` | `ProfileButton`.

### 5. `BottomTabBar`
- **Specs**: 56px height, 1px top border.
- **Tabs**: Home (`⌂`) | Scan Center (`⌕`) | Activity (`⚡`) | Guardian (`🛡`) | Settings (`⚙`).
- **Indicator**: Minimal 2px cyan active underline. No cluttered text labels.

### 6. `Card`
- **Specs**: Background `#1A1A1A` (dark) / `#FFFFFF` (light), 1px border `#2D2D2D` / `#E5E5E5`, 8px radius, 16px padding.
- **Shadow**: Subtle `0 2px 8px rgba(0,0,0,0.3)` in dark mode; clean border in light mode.

### 7. `Button` / `CyberButton`
- **Variants**:
  - `primary`: `#00D9FF` background, `#000000` text, 4px radius.
  - `secondary`: Transparent background, 1px `#2D2D2D` border, `#00D9FF` text.
  - `danger`: `#EF4444` background, `#FFFFFF` text.
- **Dimensions**: Fixed 44px tap target height.

### 8. `Badge` / `RiskBadge`
- **Threat Levels**:
  - `CRITICAL`: Dark Red `#B91C1C` fill, white text.
  - `HIGH`: Red `#EF4444` fill, white text.
  - `MEDIUM`: Orange `#F59E0B` fill, black text.
  - `LOW` / `SAFE`: Green `#22C55E` fill, white text.
- **Status Tiers**:
  - `ACTIVE` / `RESOLVED`: Green `#22C55E`.
  - `PENDING` / `OPEN`: Cyan `#00D9FF`.
  - `INACTIVE`: Grey `#6B7280`.

---

## 6. Screen Specifications

### Screen 1: Security Console (`DashboardScreen.js`)
1. **Welcome Card**: Greyscale background card, "Security Console / Welcome back, [Operator]", with live socket telemetry heartbeat indicator.
2. **Status Cards (2-Column Grid)**:
   - `GUARD SHIELD ACTIVE` (cyan top border) | Total telemetry count.
   - `ACTIVE THREATS` | Red numerical value, "Pending review".
   - `HIGH / CRITICAL` | Red numerical value, "Urgent mitigation".
   - `THREAT POSTURE` | CRITICAL / ELEVATED / SECURE autonomous status text.
3. **Threat Defense Scanners (2x2 Grid)**:
   - URL Scanner, Message Scanner, Media Scanner (Photo & Voice only), Secret Scanner.
4. **Guardian Mode & Security Activity Cards**:
   - FAMILY SHIELD and TELEMETRY badges with subtle arrow CTA.
5. **Open Incident Triage Feed**:
   - Chronological minimal cards displaying risk level badge, time ago, title, and 2-line summary.

### Screen 2: Scan Center (`ScannerHomeScreen.js`)
1. **Tab Switcher**: URL | Message | Media | Secret | Custom.
2. **Scanner Header**: Clear title and scope description.
3. **Large Input Field**: 48px height or multiline text area with cyan 44px `SCAN` button.
4. **Media Scanner Scope**:
   - **Video option is strictly removed.**
   - Photo (JPG, PNG, WebP) and Audio (WAV, MP3, M4A) deepfake detection only.
5. **Minimal Results Card**:
   - Threat level badge, Verdict (`Dangerous` / `Suspicious` / `Safe`), Risk Score (`X/100` numeric score only, no distracting bars), 3–4 bulleted key findings, and action buttons (`Report`, `Share`, `Copy`).

### Screen 3: Activity / Incidents (`IncidentListScreen.js`)
1. **Multi-Axis Filters**:
   - Status: `All` | `Open` | `Resolved`
   - Type: `All` | `Phishing` | `Malware` | `Deepfake` | `Credential` | `Scam`
   - Time: `Today` | `Last 7 days` | `Last 30 days`
2. **Incident List**:
   - Clean, tappable cards without redundant chevron icons.
   - Shows type, description, relative time (`2h ago`), risk badge, and status.

### Screen 4: Guardian Mode (`GuardianScreen.js`)
1. **Status Card**: Cyan border, "Family Shield Active / Protecting 3 dependents".
2. **Dependents List**:
   - 2-letter avatar initials box.
   - Name and role.
   - Status badge (`PROTECTED`).
   - Relative last heartbeat (`Active 5m ago`).
3. **Threat Alerts for Dependents**:
   - Real-time event cards displaying timestamp, threat type, target dependent, and auto-quarantine status.

---

## 7. Responsiveness & Cross-Platform Rules

1. **Mobile (< 768px)**:
   - Single-column vertical flow with 2-column metric cards.
   - 56px bottom navigation tab bar.
   - Copilot opens as a full-screen or slide-up modal with auto-scrolling conversation history.
2. **Web / Tablet (> 768px)**:
   - Header spans full width with 40x40px icon buttons.
   - Copilot docks as a collapsible 380px right-hand side panel without interrupting dashboard navigation.
   - Metrics grid expands to 4 columns.
3. **Theme Synchronization**:
   - Active mode stored in local secure storage.
   - On web, sets `document.documentElement.classList` (`dark` / `light`).
   - On mobile, updates React Native `ThemeContext` and dynamic `StatusBar` style.
