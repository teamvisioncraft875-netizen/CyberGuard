---
name: design-taste-frontend
description: Anti-slop frontend skill for landing pages, portfolios, and redesigns. The agent reads the brief, infers the right design direction, and ships interfaces that do not look templated. Real design systems when applicable, audit-first on redesigns, strict pre-flight check.
---

# tasteskill: Anti-Slop Frontend Skill

> Every rule below is **contextual**. None of it fires automatically. First read the brief, then pull only what fits.

---

## CYBERGUARD PROJECT DIAL OVERRIDES

The following dials are set for the CyberGuard security dashboard context and **OVERRIDE** the skill defaults below:

- **`DESIGN_VARIANCE: 3`** — Clean, structured layouts. This is a security product, not an experimental portfolio site.
- **`MOTION_INTENSITY: 2`** — Subtle only. Hover states and gentle fades. Never scroll-jacking or aggressive motion.
- **`VISUAL_DENSITY: 7`** — Dashboards need to show real information density, not excessive whitespace.

These overrides apply to all CyberGuard frontend work (`apps/web`, `apps/mobile`). Do not ask the user to change these dials — override conversationally only if explicitly requested.

**ANIMATION LIBRARY:** This project uses **GSAP with `@gsap/react`**, not `motion/react` or `framer-motion`. See the `gsap-conventions` skill for required patterns before adding any animation.

---

## 0. BRIEF INFERENCE (Read the Room Before Anything Else)

Before touching code or tweaking dials, **infer what the user actually wants**.

### 0.A Read these signals first
1. **Page kind** - landing, portfolio, redesign, editorial / blog, dashboard / product UI.
2. **Vibe words** - "minimalist", "calm", "Linear-style", "brutal", "premium", "Apple-y", "playful", "serious B2B", "dark tech".
3. **Reference signals** - URLs, screenshots, products, brands.
4. **Audience** - B2B procurement, design-conscious consumer, recruiter, internal ops team.
5. **Brand assets** - logo, color, type, photography. These are starting material, not optional.
6. **Quiet constraints** - accessibility-first, regulated industries, trust-first. These OVERRIDE aesthetic preference.

### 0.B One-line Design Read before generating
State: **"Reading this as: \<page kind\> for \<audience\>, with a \<vibe\> language, leaning toward \<design system or aesthetic family\>."**

### 0.C Ambiguous brief: ask ONE question
Never a multi-question dump. Only when the design read genuinely diverges. If you can infer from context, declare the design read and proceed.

### 0.D Anti-Default Discipline
Do not default to: AI-purple gradients, centered hero over dark mesh, three equal feature cards, generic glassmorphism on everything, infinite-loop micro-animations, Inter + slate-900.

---

## 1. THE THREE DIALS

- **`DESIGN_VARIANCE: 8`** — 1 = Perfect Symmetry, 10 = Artsy Chaos
- **`MOTION_INTENSITY: 6`** — 1 = Static, 10 = Cinematic / Physics
- **`VISUAL_DENSITY: 4`** — 1 = Art Gallery / Airy, 10 = Cockpit / Packed Data

**Baseline:** `8 / 6 / 4`. CyberGuard project overrides (`3 / 2 / 7`) take precedence over these baselines.

### 1.A Dial Inference
| Signal | VARIANCE | MOTION | DENSITY |
|---|---|---|---|
| "minimalist / clean / calm / Linear-style" | 5-6 | 3-4 | 2-3 |
| "premium consumer / Apple-y / luxury" | 7-8 | 5-7 | 3-4 |
| "playful / wild / Awwwards / experimental" | 9-10 | 8-10 | 3-4 |
| "trust-first / public-sector / regulated" | 3-4 | 2-3 | 4-5 |
| "security dashboard / data-dense B2B" | 2-4 | 1-3 | 6-8 |

---

## 2. BRIEF → DESIGN SYSTEM MAP

### 2.A Official design systems
| Brief reads as… | Reach for |
|---|---|
| Microsoft / enterprise SaaS / dashboards | `@fluentui/react-components` |
| IBM-style B2B / enterprise analytics | `@carbon/react` |
| Modern accessible React foundation | `@radix-ui/themes` |
| Modern SaaS — you own the components | shadcn/ui |
| Tailwind-based modern SaaS | Tailwind v4 utilities + `dark:` |

**One system per project.** Do not mix systems in the same tree.

### 2.B Aesthetics (no single official package)
| Aesthetic | Implementation |
|---|---|
| Glassmorphism | `backdrop-filter`, layered borders, solid-fill fallback for `prefers-reduced-transparency` |
| Dark tech / hacker | Mono + accent neon, terminal motifs |
| Kinetic typography | Native CSS animations, scroll-driven animations, GSAP for hijacks |

---

## 3. DEFAULT ARCHITECTURE & CONVENTIONS

### 3.A Stack
- **Framework:** React or Next.js. Default to Server Components (RSC).
- **Styling:** Tailwind v4 (default). Tailwind v3 only if the existing project demands it.
  - For v4: do NOT use `tailwindcss` plugin in `postcss.config.js`. Use `@tailwindcss/postcss` or the Vite plugin.
- **Animation:** **GSAP + `@gsap/react`** for CyberGuard. See `gsap-conventions` skill.
- **Fonts:** Always `next/font` or self-hosted `@font-face` + `font-display: swap`. Never `<link>` to Google Fonts in production.

### 3.B State
- Local `useState` / `useReducer` for isolated UI.
- Global state: Zustand, Jotai, or React context — only for deep prop-drilling avoidance.
- NEVER `useState` for continuous pointer / scroll values. Use GSAP observer/ticker.

### 3.C Icons
- **Priority order:** `@phosphor-icons/react`, `hugeicons-react`, `@radix-ui/react-icons`, `@tabler/icons-react`.
- `lucide-react` acceptable only when the project already depends on it.
- NEVER hand-roll SVG icons. One family per project.

### 3.D Emoji Policy
Discouraged by default. Replace with icon-library glyphs.

### 3.E Responsiveness
- Breakpoints: `sm 640`, `md 768`, `lg 1024`, `xl 1280`, `2xl 1536`.
- Max-width: `max-w-[1400px] mx-auto` or `max-w-7xl`.
- Viewport height: NEVER `h-screen`. ALWAYS `min-h-[100dvh]`.
- Layout: CSS Grid over flexbox percentage math.

### 3.F Dependency Verification (mandatory)
Before importing ANY 3rd-party library, check `package.json`. If missing, output the install command first.

---

## 4. DESIGN ENGINEERING DIRECTIVES

### 4.1 Typography
- Display / Headlines: `text-4xl md:text-6xl tracking-tighter leading-none`
- Body: `text-base text-gray-600 leading-relaxed max-w-[65ch]`
- Font choice: `Geist`, `Outfit`, `Cabinet Grotesk`, `Satoshi`. Discouraged default: `Inter`.
- SERIF DISCIPLINE: Serif only when brand brief explicitly names a serif or the aesthetic is genuinely editorial/luxury.
- BANNED default serifs: `Fraunces`, `Instrument_Serif`.

### 4.2 Color
- Max 1 accent. Saturation < 80%.
- No AI-purple gradients as default.
- One palette per project. COLOR CONSISTENCY LOCK: accent chosen = used everywhere.

### 4.3 Layout
- ANTI-CENTER BIAS: Avoid centered Hero/H1 when `DESIGN_VARIANCE > 4`. Use split-screen or asymmetric layouts.
- SHAPE CONSISTENCY LOCK: One corner-radius scale per page.

### 4.4 Interactive States (mandatory)
- Loading: skeletal loaders matching final layout shape.
- Empty States: beautifully composed, shows how to populate.
- Error States: inline for forms, toasts for transient.
- Tactile Feedback: `-translate-y-[1px]` or `scale-[0.98]` on `:active`.
- BUTTON CONTRAST CHECK: WCAG AA minimum (4.5:1 body, 3:1 large text).
- CTA BUTTON WRAP BAN: button text on one line at desktop.

### 4.5 Layout Hard Rules (failing = broken work)
- Hero fits in initial viewport. Headline max 2 lines desktop.
- Nav on single line at desktop. Height cap: 80px max.
- Section-Layout-Repetition Ban: each layout family appears at most once per page.
- EYEBROW RESTRAINT: max 1 eyebrow per 3 sections.
- Mobile collapse explicit per section.

### 4.6 Visual Assets
- Priority: image-generation tool → real web images → tell the user.
- Div-based fake screenshots are banned.
- Fake-precise numbers (92%, 4.1×) must be real data or labeled as mock.

### 4.7 Copy Self-Audit (mandatory before ship)
Re-read every visible string. Flag grammatically broken, unclear referent, AI-hallucination, or "LLM trying to sound thoughtful" strings and rewrite them.
