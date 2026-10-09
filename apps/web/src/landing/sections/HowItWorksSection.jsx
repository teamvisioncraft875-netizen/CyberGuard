import React, { useEffect, useRef } from 'react';

/* ─────────────────────────────────────────────
   STEP DATA
───────────────────────────────────────────── */
const STEPS = [
  {
    n: '01',
    title: 'Install App',
    desc: 'Download CYBERGUARD on iOS, Android, or Desktop. One-tap setup, no configuration needed.',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
        <polyline points="7 10 12 15 17 10" />
        <line x1="12" y1="15" x2="12" y2="3" />
      </svg>
    ),
  },
  {
    n: '02',
    title: 'Scan & Protect',
    desc: 'Real-time scanning of links, messages, images, and files. 6 detection engines run simultaneously.',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
  },
  {
    n: '03',
    title: 'Get Alerted',
    desc: 'Instant push notifications on high-risk threats. Severity levels: Low · Medium · High · Critical.',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 01-3.46 0" />
      </svg>
    ),
  },
  {
    n: '04',
    title: 'Respond Automatically',
    desc: 'AI-driven SOAR playbooks execute responses instantly — block, quarantine, or escalate.',
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    ),
  },
];

/* ─────────────────────────────────────────────
   RIGHT COLUMN — TERMINAL MOCKUP
   Animated "live workflow" terminal card
───────────────────────────────────────────── */
const TERMINAL_LINES = [
  { delay: 0,    type: 'cmd',     text: '$ cyberguard init --device mobile' },
  { delay: 600,  type: 'success', text: '✓  Device registered: iPhone 15 Pro' },
  { delay: 1100, type: 'cmd',     text: '$ cyberguard scan --mode realtime' },
  { delay: 1700, type: 'info',    text: '›  Engine 1/6 — Phishing detector   active' },
  { delay: 2100, type: 'info',    text: '›  Engine 2/6 — URL analyser        active' },
  { delay: 2500, type: 'info',    text: '›  Engine 3/6 — Deepfake detector   active' },
  { delay: 2900, type: 'info',    text: '›  Engine 4/6 — Secret scanner      active' },
  { delay: 3300, type: 'info',    text: '›  Engine 5/6 — Malware classifier  active' },
  { delay: 3700, type: 'info',    text: '›  Engine 6/6 — Anomaly detector    active' },
  { delay: 4200, type: 'divider', text: '' },
  { delay: 4400, type: 'warn',    text: '⚠  THREAT DETECTED — risk: HIGH' },
  { delay: 4800, type: 'dim',     text: '   type:    Phishing URL' },
  { delay: 5000, type: 'dim',     text: '   source:  WhatsApp message' },
  { delay: 5200, type: 'dim',     text: '   target:  credentials/banking' },
  { delay: 5600, type: 'divider', text: '' },
  { delay: 5800, type: 'cmd',     text: '$ cyberguard respond --auto' },
  { delay: 6300, type: 'success', text: '✓  URL blocked & quarantined' },
  { delay: 6700, type: 'success', text: '✓  Alert pushed to device' },
  { delay: 7100, type: 'success', text: '✓  Incident logged — ID #CG-00847' },
  { delay: 7500, type: 'success', text: '✓  Playbook executed in 1.2s' },
];

const LINE_COLORS = {
  cmd:     '#E5E5E5',
  success: '#22C55E',
  info:    '#6B7280',
  warn:    '#F59E0B',
  dim:     '#444',
  divider: '#222',
};

function TerminalMockup() {
  const lineRefs = useRef([]);
  const hasAnimated = useRef(false);
  const containerRef = useRef(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !hasAnimated.current) {
          hasAnimated.current = true;
          TERMINAL_LINES.forEach((line, i) => {
            setTimeout(() => {
              const el = lineRefs.current[i];
              if (el) {
                el.style.opacity = '1';
                el.style.transform = 'translateY(0)';
              }
            }, line.delay);
          });
        }
      },
      { threshold: 0.3 }
    );
    if (containerRef.current) observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={containerRef} style={{
      background: '#0D0D0D',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 14,
      overflow: 'hidden',
      boxShadow: '0 32px 80px rgba(0,0,0,0.6), 0 1px 0 rgba(255,255,255,0.04) inset',
    }}>
      {/* Title bar */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', alignItems: 'center', gap: 8,
        background: '#111',
      }}>
        <div style={{ display: 'flex', gap: 6 }}>
          {['#2A2A2A', '#2A2A2A', '#2A2A2A'].map((c, i) => (
            <div key={i} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />
          ))}
        </div>
        <span style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '0.6875rem', color: '#444',
          marginLeft: 8, letterSpacing: '0.04em',
        }}>
          cyberguard — terminal
        </span>
        {/* Live badge */}
        <div style={{
          marginLeft: 'auto',
          display: 'flex', alignItems: 'center', gap: 5,
          fontFamily: 'Inter, sans-serif',
          fontSize: '0.625rem', fontWeight: 600,
          letterSpacing: '0.08em', textTransform: 'uppercase',
          color: '#22C55E',
        }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%', background: '#22C55E',
            animation: 'pulse-green 2s ease-in-out infinite',
          }} />
          LIVE
        </div>
      </div>

      {/* Terminal body */}
      <div style={{
        padding: '20px',
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: '0.75rem',
        lineHeight: 1.8,
        minHeight: '380px',
        overflowY: 'auto',
      }}>
        {TERMINAL_LINES.map((line, i) => {
          if (line.type === 'divider') {
            return (
              <div
                key={i}
                ref={el => lineRefs.current[i] = el}
                style={{
                  height: 1,
                  background: 'rgba(255,255,255,0.05)',
                  margin: '10px 0',
                  opacity: 0,
                  transform: 'translateY(6px)',
                  transition: 'opacity 0.3s ease, transform 0.3s ease',
                }}
              />
            );
          }
          return (
            <div
              key={i}
              ref={el => lineRefs.current[i] = el}
              style={{
                color: LINE_COLORS[line.type] || '#888',
                opacity: 0,
                transform: 'translateY(6px)',
                transition: 'opacity 0.3s ease, transform 0.3s ease',
                fontWeight: line.type === 'cmd' ? 500 : 400,
              }}
            >
              {line.text}
            </div>
          );
        })}
        {/* Blinking cursor */}
        <div style={{
          display: 'inline-block',
          width: 8, height: 14,
          background: '#00D9FF',
          marginLeft: 2,
          animation: 'blink-cursor 1.1s step-end infinite',
          verticalAlign: 'middle',
          borderRadius: 1,
          opacity: 0.8,
        }} />
      </div>

      <style>{`
        @keyframes pulse-green {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.4; }
        }
        @keyframes blink-cursor {
          0%, 100% { opacity: 0.8; }
          50%       { opacity: 0; }
        }
      `}</style>
    </div>
  );
}

/* ─────────────────────────────────────────────
   MAIN COMPONENT
───────────────────────────────────────────── */
export default function HowItWorksSection() {
  const stepRefs   = useRef([]);
  const rightRef   = useRef(null);
  const sectionRef = useRef(null);
  const revealed   = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !revealed.current) {
          revealed.current = true;

          // Stagger steps
          stepRefs.current.forEach((el, i) => {
            if (!el) return;
            setTimeout(() => {
              el.style.transition = 'opacity 0.65s ease, transform 0.65s ease';
              el.style.opacity = '1';
              el.style.transform = 'translateX(0)';
            }, i * 120);
          });

          // Right panel
          if (rightRef.current) {
            setTimeout(() => {
              rightRef.current.style.transition = 'opacity 0.7s ease 0.2s, transform 0.7s ease 0.2s';
              rightRef.current.style.opacity = '1';
              rightRef.current.style.transform = 'translateY(0)';
            }, 100);
          }
        }
      },
      { threshold: 0.12 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      id="how-it-works"
      ref={sectionRef}
      style={{
        position: 'relative',
        overflow: 'hidden',
        paddingTop: '100px',
        paddingBottom: 0,
        background: '#0A0A0A',
      }}
    >
      {/* ── Landscape background ── */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'url(/hero-bg.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center 55%',
        backgroundRepeat: 'no-repeat',
        opacity: 0.18,
        filter: 'saturate(0.4)',
      }} />

      {/* ── Top gradient: black → transparent ── */}
      <div style={{
        position: 'absolute',
        top: 0, left: 0, right: 0,
        height: '45%',
        background: 'linear-gradient(to bottom, #0A0A0A 0%, transparent 100%)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />

      {/* ── Bottom gradient: transparent → black ── */}
      <div style={{
        position: 'absolute',
        bottom: 0, left: 0, right: 0,
        height: '55%',
        background: 'linear-gradient(to top, #0A0A0A 0%, transparent 100%)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />

      {/* ── CONTENT ── */}
      <div style={{
        position: 'relative', zIndex: 2,
        maxWidth: '1440px',
        marginInline: 'auto',
        paddingInline: 'clamp(1.5rem, 5vw, 6rem)',
      }}>

        {/* ── Section header ── */}
        <div style={{ marginBottom: '64px' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            fontFamily: 'Inter, sans-serif',
            fontSize: '0.75rem', fontWeight: 500,
            letterSpacing: '0.1em', textTransform: 'uppercase',
            color: '#666',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: 9999,
            padding: '5px 14px',
            marginBottom: '1.5rem',
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#666', display: 'inline-block' }} />
            The Security Workflow
          </div>

          <h2 style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
            fontWeight: 650,
            fontSize: 'clamp(1.75rem, 2.8vw, 2.35rem)',
            lineHeight: 1.22,
            letterSpacing: '-0.025em',
            color: '#fff',
            marginBottom: '1.25rem',
            maxWidth: '580px',
          }}>
            Set up once. Protect everything.
          </h2>
          <p style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 'clamp(1rem, 1.8vw, 1.125rem)',
            lineHeight: 1.7,
            color: '#777',
            maxWidth: '480px',
          }}>
            From threat detection to automated response — all in your pocket.
          </p>
        </div>

        {/* ── Two-column layout ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 440px), 1fr))',
          gap: 'clamp(2.5rem, 6vw, 6rem)',
          alignItems: 'start',
          paddingBottom: '100px',
        }}>

          {/* ── LEFT: Steps ── */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
            {STEPS.map((step, i) => {
              const isLast = i === STEPS.length - 1;
              return (
                <div
                  key={step.n}
                  ref={el => stepRefs.current[i] = el}
                  style={{
                    display: 'flex',
                    gap: '1.25rem',
                    opacity: 0,
                    transform: 'translateX(-20px)',
                    position: 'relative',
                  }}
                >
                  {/* Left: number + connector */}
                  <div style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    flexShrink: 0,
                    paddingTop: 2,
                  }}>
                    {/* Step circle */}
                    <div style={{
                      width: 40, height: 40,
                      borderRadius: '50%',
                      background: '#141414',
                      border: '1px solid rgba(255,255,255,0.1)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      flexShrink: 0,
                      color: '#00D9FF',
                      position: 'relative',
                      zIndex: 1,
                    }}>
                      {step.icon}
                    </div>

                    {/* Connector line */}
                    {!isLast && (
                      <div style={{
                        width: 1,
                        flex: 1,
                        minHeight: '48px',
                        background: 'linear-gradient(to bottom, rgba(255,255,255,0.08), transparent)',
                        margin: '6px 0',
                      }} />
                    )}
                  </div>

                  {/* Right: content */}
                  <div style={{ paddingBottom: isLast ? 0 : '2.5rem', paddingTop: '6px' }}>
                    {/* Step label */}
                    <span style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.6875rem',
                      fontWeight: 600,
                      color: '#333',
                      letterSpacing: '0.12em',
                      textTransform: 'uppercase',
                      display: 'block',
                      marginBottom: '6px',
                    }}>
                      Step {step.n}
                    </span>

                    {/* Step title */}
                    <h3 style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '1rem',
                      fontWeight: 700,
                      color: '#fff',
                      letterSpacing: '-0.01em',
                      marginBottom: '0.5rem',
                    }}>
                      {step.title}
                    </h3>

                    {/* Step desc */}
                    <p style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '0.875rem',
                      fontWeight: 400,
                      color: '#666',
                      lineHeight: 1.65,
                    }}>
                      {step.desc}
                    </p>
                  </div>
                </div>
              );
            })}

            {/* CTA under steps */}
            <div style={{ marginTop: '2.5rem' }}>
              <button
                onClick={() => document.querySelector('#download')?.scrollIntoView({ behavior: 'smooth' })}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 8,
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '0.875rem', fontWeight: 600,
                  color: '#0F0F0F', background: '#fff',
                  border: 'none', borderRadius: 9999,
                  height: 44, padding: '0 22px',
                  cursor: 'pointer', transition: 'background 0.2s, transform 0.15s',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = '#E8E8E8'; e.currentTarget.style.transform = 'scale(1.02)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = '#fff'; e.currentTarget.style.transform = 'scale(1)'; }}
              >
                Get started — it's free
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </button>
            </div>
          </div>

          {/* ── RIGHT: Terminal mockup ── */}
          <div
            ref={rightRef}
            style={{ opacity: 0, transform: 'translateY(24px)' }}
          >
            <TerminalMockup />

            {/* Stats row under terminal */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '1px',
              background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 12,
              overflow: 'hidden',
              marginTop: '1.25rem',
            }}>
              {[
                { val: '< 1.2s', label: 'Detection speed' },
                { val: '99.9%',  label: 'Uptime SLA' },
                { val: '6',      label: 'Detection engines' },
              ].map((s, i) => (
                <div key={i} style={{
                  background: '#111',
                  padding: '16px',
                  textAlign: 'center',
                }}>
                  <p style={{
                    fontFamily: 'Inter, sans-serif',
                    fontSize: '1.1875rem', fontWeight: 700,
                    color: '#fff', letterSpacing: '-0.02em',
                    marginBottom: 3,
                  }}>
                    {s.val}
                  </p>
                  <p style={{
                    fontFamily: 'Inter, sans-serif',
                    fontSize: '0.6875rem', color: '#444',
                  }}>
                    {s.label}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
