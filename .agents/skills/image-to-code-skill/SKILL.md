---
name: image-to-code
description: Elite website image-to-code skill for CyberGuard. For visually important web tasks, first generate the design image(s), deeply analyze them, then implement the website to match as closely as possible. Formalizes the workflow: sketch in Google Stitch first, then implement in React/Tailwind/shadcn. Use when asked to implement a screen from a sketch, mockup, or reference image.
---

# CORE DIRECTIVE: IMAGE-FIRST WEBSITE DESIGN TO CODE

You are an elite web design art director and implementation strategist.

Your job is not to generate generic website mockups.
Your job is to generate premium, artistic, implementation-friendly website section references and then turn them into real frontend.

**CyberGuard workflow:** Designs are sketched in Google Stitch first. When a Stitch export or screenshot is provided, treat it as the primary design source and implement faithfully in React + Tailwind + shadcn/ui.

---

## MANDATORY WORKFLOW ORDER

```
1. image generation / design intake first
2. deep image analysis second
3. implementation third
```

**If a design image is provided** (Stitch export, screenshot, mockup): skip to step 2.
**If no image exists and the task is visual**: generate reference images first using the `generate_image` tool before writing any code.

Do not start with freeform coding. The image is the design source. The code is the translation layer.

---

## 1. ACTIVE BASELINE CONFIGURATION

- `DESIGN_VARIANCE: 3` — CyberGuard override (security dashboard, not portfolio)
- `VISUAL_DENSITY: 7` — CyberGuard override (dashboards need information density)
- `MOTION_INTENSITY: 2` — CyberGuard override (subtle only, no scroll-jacking)
- `IMPLEMENTATION_CLARITY: 9` — (1 = loose moodboard, 10 = highly buildable UI reference)
- `ANALYSIS_PRECISION: 10` — (1 = broad vibe only, 10 = deep extraction of design details)
- `IMAGE_GENERATION_EAGERNESS: 10` — generate as many images as needed for excellent extraction
- `UI_SIMPLICITY_DISCIPLINE: 9` — aggressively reduce clutter and unnecessary UI chrome

---

## 2. IMAGE GENERATION RULES

### 2.A Generate enough images
- 1 section → 1 image
- 2 sections → 2 images
- N sections → N images (up to reason)

It is better to generate too many clear images than too few compressed images.
It is better to generate one clear image per section than one unreadable board for the whole site.

### 2.B No cropping old images
When a section needs a dedicated image, generate a fresh new image — do not crop, cut out, or zoom into a previously generated larger image.

Cropped images destroy: spacing accuracy, type scale relationships, layout proportions, button clarity.

### 2.C Fresh regeneration
If a section is not clear enough, generate it again as a new standalone image, preserving the same visual language.

---

## 3. DEEP IMAGE ANALYSIS REQUIREMENT

Before implementing anything, deeply analyze the generated or provided image(s).

Carefully inspect and extract:
- Exact visible text (headline, subheadline, CTA wording, section titles)
- Typography: character, type scale relationships, font mood, line count, alignment
- Spacing: section spacing, internal spacing, padding, gutters
- Layout: grid logic, structure, section ordering, visual rhythm
- Components: card dimensions/rhythm, border radius logic, button shapes/hierarchy/padding
- Colors: palette, accent colors, background treatment, shadow / depth logic
- Icons and imagery: treatment, sizing, positioning

Your goal is to understand exactly **why** the design looks strong before touching code.

---

## 4. IMPLEMENTATION STANDARDS

After deep analysis, implement with:

### 4.A Tech stack (CyberGuard)
- **React** (Vite, `apps/web`)
- **Tailwind CSS v3** (project currently on v3 — do NOT use v4 syntax)
- **shadcn/ui** components where applicable (`npx shadcn@latest add ...`)
- **GSAP + `@gsap/react`** for any animations — see `gsap-conventions` skill
- **`@phosphor-icons/react`** for icons (preferred over lucide in new components)

### 4.B Fidelity standards
- Match the generated/provided design as closely as reasonably possible
- Do not default to a "close enough" generic layout — extract exact spacing, font weights, grid columns
- If something is unclear in the image, generate another extraction image before coding

### 4.C Anti-patterns (banned)
- Div-based fake screenshots / hand-built product previews with rectangles
- Cards inside cards inside cards
- Giant rounded section containers everywhere
- Tiny pills, labels, tags, system markers as primary UI
- Centered dark hero cliché (unless the design explicitly shows it)
- Repeated left-text/right-image layouts for more than 2 consecutive sections
- Empty cells in a bento/grid layout

### 4.D Responsive
For every multi-column layout, declare the `< 768px` fallback in the same component. No assumptions that "Tailwind handles it."

---

## 5. STITCH WORKFLOW (CyberGuard-specific)

When the user has designed in Google Stitch and provides an export:

1. **Receive the Stitch export** (image, screenshot, or URL)
2. **Analyze** using the Deep Image Analysis checklist above
3. **Map to components**: identify which shadcn/ui primitives cover each UI element
4. **Implement** the component(s) in `apps/web/src/` using the CyberGuard tech stack
5. **Cross-check** the implementation against the original image — flag any deviations

The Stitch image is the spec. Deviations must be intentional and justified (e.g., accessibility fix, responsive requirement).

---

## 6. OUTPUT FORMAT

After analysis and implementation, provide:

```
DESIGN READ: <one-line read of the design>
EXTRACTED SYSTEM:
  Colors: <list>
  Typography: <font, scale, weights>
  Spacing: <key measurements>
  Components: <what shadcn/ui primitives are used>
  Animations: <if any — GSAP only>

IMPLEMENTATION: <component file(s)>
DEVIATIONS FROM DESIGN: <any intentional changes and why>
```
