---
name: web-design-guidelines
description: Review UI code for Web Interface Guidelines compliance. Use when asked to "review my UI", "check accessibility", "audit design", "review UX", or "check my site against best practices".
metadata:
  author: vercel
  version: "1.0.0"
  argument-hint: <file-or-pattern>
---

# Web Interface Guidelines

Review files for compliance with Web Interface Guidelines.

## How It Works

1. Fetch the latest guidelines from the source URL below
2. Read the specified files (or prompt user for files/pattern)
3. Check against all rules in the fetched guidelines
4. Output findings with line references, severity, and recommended fixes

## Source

Guidelines are fetched live from:
https://vercel.com/design/introduction

## Usage

Run this skill against a file, directory, or glob pattern:
- `review my UI in apps/web/src/components/`
- `check accessibility of apps/web/src/pages/Dashboard.jsx`
- `audit design of the incident feed component`

The skill fetches the latest Vercel Web Interface Guidelines and checks:

### Accessibility
- Semantic HTML elements used correctly (`<nav>`, `<main>`, `<article>`, `<section>`, etc.)
- All interactive elements reachable via keyboard
- Focus indicators visible and not hidden with `outline: none`
- Images have meaningful `alt` text (not empty unless decorative)
- Color contrast meets WCAG AA minimum (4.5:1 for body text, 3:1 for large text / UI components)
- Form inputs have associated `<label>` elements (not placeholder-only)
- Error messages announced to screen readers (aria-live or role="alert")
- Sufficient touch target size (minimum 44×44px)

### Layout
- No use of `h-screen` on content sections (use `min-h-[100dvh]` instead)
- Consistent max-width container (`max-w-7xl` or `max-w-[1400px] mx-auto`)
- CSS Grid used for multi-column layouts (not flexbox percentage math)
- Mobile collapse declared explicitly per component
- Navigation renders on a single line at desktop

### Typography
- Consistent type scale (no arbitrary font sizes without a clear scale)
- Line length limited to ~65ch for body text (`max-w-[65ch]`)
- `line-height` adequate for body text (≥ 1.5)
- No placeholder text used as labels

### Interactivity
- All interactive states covered: default, hover, focus, active, disabled, loading
- Loading states use skeleton loaders (not generic spinners where layout is known)
- Error messages shown inline for forms, not only via toast/alert
- Buttons have visible text (not icon-only without aria-label)

### Performance Signals
- Images have explicit `width` and `height` attributes (prevents CLS)
- Fonts loaded with `font-display: swap`
- No blocking scripts in `<head>` without `defer` or `async`

## Output Format

For each finding, output:
```
[SEVERITY] Component/File:Line — Rule violated
  Found: <what was found>
  Fix:   <recommended fix>
```

Severity levels: `ERROR` (accessibility/contrast failure), `WARNING` (design quality issue), `INFO` (best practice).

Summarize with total counts per severity at the end.
