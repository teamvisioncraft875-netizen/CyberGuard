---
name: gsap-conventions
description: GSAP animation conventions for CyberGuard's React frontend. Use when adding any animation, transition, or motion effect to a component.
---

# GSAP Conventions for CyberGuard

- Use the official `useGSAP` hook from `@gsap/react`, not raw `useEffect` + manual cleanup.
- Scope one `ref` per container/section, not one per animated element. Target children inside that container by CSS class name via `gsap.context()`, so most animations need zero additional refs.
- Keep animations subtle and calm — this is a security dashboard, not a marketing site. Prefer opacity/transform fades over bounce, elastic, or attention-grabbing easing curves.
- New incident/alert appearing: a brief fade + slight upward slide, nothing more.
- Never animate on every render — animations trigger once per genuinely new event (a new incident arriving), not on data refetch or re-render.
- Keep GSAP usage isolated to components that actually need motion — most of the dashboard (tables, forms, static cards) should have no animation at all.
