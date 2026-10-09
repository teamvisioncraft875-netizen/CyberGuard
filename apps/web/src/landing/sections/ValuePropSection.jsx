import React, { useState, useEffect, useRef } from 'react';

/* ─────────────────────────────────────────────
   TAB DATA
───────────────────────────────────────────── */
const TABS = [
  {
    id: 'personal',
    label: 'Personal',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" />
      </svg>
    ),
    headline: 'Security in your pocket',
    description: 'Real-time protection for links, messages, media, and secrets — all on your personal device.',
    metrics: [
      { label: 'Threats blocked today', value: '24' },
      { label: 'Scans completed', value: '1.2k' },
      { label: 'Security score', value: '94' },
    ],
    mockupItems: [
      { status: 'safe',    text: 'URL scan — google.com', sub: 'No threats detected' },
      { status: 'warning', text: 'Phishing attempt blocked', sub: 'WhatsApp message • 2 min ago' },
      { status: 'safe',    text: 'Deepfake check passed', sub: 'Image verified authentic' },
      { status: 'danger',  text: 'Credential exposure', sub: 'Found in data breach' },
    ],
  },
  {
    id: 'enterprise',
    label: 'Enterprise',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M3 9h18M9 21V9" />
      </svg>
    ),
    headline: 'SOC-grade command center',
    description: 'AI Copilot, SOAR playbooks, incident triage, and real-time threat hunting for security teams.',
    metrics: [
      { label: 'MTTR reduction', value: '78%' },
      { label: 'Incidents resolved', value: '3.4k' },
      { label: 'Active agents', value: '12' },
    ],
    mockupItems: [
      { status: 'danger',  text: 'Critical — Ransomware attempt', sub: 'Endpoint 192.168.1.45 • Now' },
      { status: 'warning', text: 'High — Lateral movement', sub: 'Internal network • 4 min ago' },
      { status: 'safe',    text: 'SOAR playbook triggered', sub: 'Auto-remediated • 6 min ago' },
      { status: 'safe',    text: 'AI Copilot report ready', sub: 'Weekly threat summary' },
    ],
  },
  {
    id: 'ai',
    label: 'AI Copilot',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2a10 10 0 110 20 10 10 0 010-20z" /><path d="M12 8v4l3 3" />
      </svg>
    ),
    headline: 'Ask. Analyze. Respond.',
    description: 'Natural language queries, automated triage, and intelligent response suggestions — powered by LLMs.',
    metrics: [
      { label: 'Avg response time', value: '1.2s' },
      { label: 'Queries answered', value: '890k' },
      { label: 'Accuracy', value: '97%' },
    ],
    mockupItems: [
      { status: 'safe',    text: '"Summarize today\'s incidents"', sub: 'Copilot • AI generated' },
      { status: 'safe',    text: '"Why was this flagged?"', sub: 'Explained in plain English' },
      { status: 'warning', text: '"Is this IP malicious?"', sub: 'Cross-referenced 12 threat feeds' },
      { status: 'safe',    text: 'Playbook auto-generated', sub: 'Based on incident pattern' },
    ],
  },
  {
    id: 'ecosystem',
    label: 'Ecosystem',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="2" /><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
      </svg>
    ),
    headline: 'Open. Extensible. Integrated.',
    description: 'REST API, webhook triggers, SIEM integrations, and mobile SDK — security that fits your stack.',
    metrics: [
      { label: 'API endpoints', value: '48' },
      { label: 'Integrations', value: '30+' },
      { label: 'Uptime SLA', value: '99.9%' },
    ],
    mockupItems: [
      { status: 'safe',    text: 'Splunk integration active', sub: 'Live log streaming' },
      { status: 'safe',    text: 'Slack alerts configured', sub: 'Critical severity only' },
      { status: 'safe',    text: 'REST API — 2.1k req/min', sub: 'Within rate limits' },
      { status: 'warning', text: 'Webhook retry queued', sub: 'Endpoint timeout • Retrying' },
    ],
  },
];

/* ─────────────────────────────────────────────
   VALUE POINTS
───────────────────────────────────────────── */
const VALUE_POINTS = [
  {
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00D9FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
    title: 'Personal Protection',
    desc: 'URL scanning, phishing detection, and deepfake verification — running silently in the background, every second of every day.',
  },
  {
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00D9FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8M12 17v4" />
        <path d="M7 8h10M7 11h6" />
      </svg>
    ),
    title: 'Enterprise SOC',
    desc: 'AI Copilot, SOAR automation, and threat hunting tools that compress hours of analyst work into automated playbooks.',
  },
  {
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00D9FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" /><path d="M12 8v4l3 3" />
      </svg>
    ),
    title: 'Unified Intelligence',
    desc: 'One backend powers both modes. Every threat model update protects personal users and enterprise teams simultaneously.',
  },
];

/* ─────────────────────────────────────────────
   STATUS DOT
───────────────────────────────────────────── */
const STATUS_COLORS = {
  safe:    { dot: '#22C55E', bg: 'rgba(34,197,94,0.08)',   border: 'rgba(34,197,94,0.15)' },
  warning: { dot: '#F59E0B', bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.15)' },
  danger:  { dot: '#EF4444', bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.15)' },
};

/* ─────────────────────────────────────────────
   MAIN COMPONENT
───────────────────────────────────────────── */
export default function ValuePropSection() {
  const [activeTab, setActiveTab] = useState('personal');
  const [transitioning, setTransitioning] = useState(false);
  const sectionRef  = useRef(null);
  const leftRef     = useRef(null);
  const rightRef    = useRef(null);
  const revealedRef = useRef(false);

  const currentTab = TABS.find(t => t.id === activeTab);

  /* ── Scroll reveal ── */
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !revealedRef.current) {
          revealedRef.current = true;
          [leftRef.current, rightRef.current].forEach((el, i) => {
            if (!el) return;
            el.style.transition = `opacity 0.7s ease ${i * 0.15}s, transform 0.7s ease ${i * 0.15}s`;
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
          });
        }
      },
      { threshold: 0.15 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  /* ── Tab switch with fade ── */
  const switchTab = (id) => {
    if (id === activeTab || transitioning) return;
    setTransitioning(true);
    setTimeout(() => {
      setActiveTab(id);
      setTransitioning(false);
    }, 180);
  };

  return (
    <section
      id="features"
      ref={sectionRef}
      style={{
        background: '#0F0F0F',
        paddingTop: '80px',
        paddingBottom: '100px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Anchor for About link */}
      <div id="about" style={{ position: 'absolute', top: 0, left: 0 }} />

      <div style={{
        maxWidth: '1440px',
        marginInline: 'auto',
        paddingInline: 'clamp(1.5rem, 5vw, 6rem)',
      }}>

        {/* ── Section Overline ── */}
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
            Value Proposition
          </div>

          <h2 style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
            fontWeight: 650,
            fontSize: 'clamp(1.75rem, 2.8vw, 2.35rem)',
            lineHeight: 1.22,
            letterSpacing: '-0.025em',
            color: '#fff',
            maxWidth: '680px',
            marginBottom: '1.25rem',
          }}>
            One platform. Two security experiences.
          </h2>

          <p style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
            fontSize: 'clamp(0.95rem, 1.8vw, 1.1rem)',
            lineHeight: 1.65,
            color: '#888',
            maxWidth: '560px',
          }}>
            CYBERGUARD protects personal users from everyday cyber threats while empowering
            enterprises with AI-driven security operations.
          </p>
        </div>

        {/* ── Two-column layout ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 480px), 1fr))',
          gap: 'clamp(2rem, 5vw, 5rem)',
          alignItems: 'start',
        }}>

          {/* ── LEFT: Value points ── */}
          <div
            ref={leftRef}
            style={{ opacity: 0, transform: 'translateY(28px)' }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
              {VALUE_POINTS.map((vp, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    gap: '1.25rem',
                    padding: '1.75rem 0',
                    borderBottom: i < VALUE_POINTS.length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none',
                  }}
                >
                  {/* Icon box */}
                  <div style={{
                    width: 42, height: 42, borderRadius: 10,
                    background: 'rgba(0,217,255,0.06)',
                    border: '1px solid rgba(0,217,255,0.12)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                    marginTop: 2,
                  }}>
                    {vp.icon}
                  </div>
                  {/* Text */}
                  <div>
                    <p style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '0.9375rem', fontWeight: 600,
                      color: '#fff', marginBottom: '0.5rem',
                      letterSpacing: '-0.01em',
                    }}>
                      {vp.title}
                    </p>
                    <p style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '0.875rem', fontWeight: 400,
                      color: '#777', lineHeight: 1.65,
                    }}>
                      {vp.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* CTA under value points */}
            <div style={{ marginTop: '2.5rem', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <button
                onClick={() => document.querySelector('#download')?.scrollIntoView({ behavior: 'smooth' })}
                style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '0.875rem', fontWeight: 600,
                  color: '#0F0F0F', background: '#fff',
                  border: 'none', borderRadius: 9999,
                  height: 44, padding: '0 22px',
                  cursor: 'pointer', transition: 'background 0.2s',
                  letterSpacing: '-0.01em',
                }}
                onMouseEnter={e => e.currentTarget.style.background = '#E8E8E8'}
                onMouseLeave={e => e.currentTarget.style.background = '#fff'}
              >
                Download now
              </button>
              <button
                onClick={() => document.querySelector('#pricing')?.scrollIntoView({ behavior: 'smooth' })}
                style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '0.875rem', fontWeight: 500,
                  color: '#aaa', background: 'transparent',
                  border: '1px solid rgba(255,255,255,0.12)', borderRadius: 9999,
                  height: 44, padding: '0 22px',
                  cursor: 'pointer', transition: 'border-color 0.2s, color 0.2s',
                }}
                onMouseEnter={e => { e.currentTarget.style.color = '#fff'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.28)'; }}
                onMouseLeave={e => { e.currentTarget.style.color = '#aaa'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)'; }}
              >
                See pricing →
              </button>
            </div>
          </div>

          {/* ── RIGHT: Mockup + Tabs ── */}
          <div
            ref={rightRef}
            style={{ opacity: 0, transform: 'translateY(28px)' }}
          >
            {/* ── Tab Switcher ── */}
            <div style={{
              display: 'flex',
              gap: '4px',
              marginBottom: '1.5rem',
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.07)',
              borderRadius: 12,
              padding: '4px',
            }}>
              {TABS.map(tab => {
                const isActive = tab.id === activeTab;
                return (
                  <button
                    key={tab.id}
                    onClick={() => switchTab(tab.id)}
                    style={{
                      flex: 1,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '0.8125rem', fontWeight: isActive ? 600 : 400,
                      color: isActive ? '#fff' : '#555',
                      background: isActive ? '#1E1E1E' : 'transparent',
                      border: isActive ? '1px solid rgba(255,255,255,0.1)' : '1px solid transparent',
                      borderRadius: 8,
                      padding: '8px 6px',
                      cursor: 'pointer',
                      transition: 'all 0.18s ease',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    <span style={{ color: isActive ? '#00D9FF' : '#444', transition: 'color 0.18s' }}>
                      {tab.icon}
                    </span>
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* ── Mockup Card ── */}
            <div
              style={{
                background: '#141414',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 16,
                overflow: 'hidden',
                boxShadow: '0 24px 64px rgba(0,0,0,0.5), 0 1px 0 rgba(255,255,255,0.04) inset',
                transition: 'opacity 0.18s ease',
                opacity: transitioning ? 0 : 1,
              }}
            >
              {/* Card header bar */}
              <div style={{
                padding: '14px 18px',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {/* Traffic lights */}
                  {['#3A3A3A', '#3A3A3A', '#3A3A3A'].map((c, i) => (
                    <div key={i} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />
                  ))}
                </div>
                <div style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.6875rem', color: '#444',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.06)',
                  borderRadius: 6, padding: '3px 10px',
                }}>
                  cyberguard.app/{currentTab.id}
                </div>
                <div style={{ width: 42 }} />
              </div>

              {/* Tab header inside card */}
              <div style={{
                padding: '20px 20px 12px',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
              }}>
                <p style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '0.8125rem', fontWeight: 600,
                  color: '#fff', marginBottom: 4,
                  letterSpacing: '-0.01em',
                }}>
                  {currentTab.headline}
                </p>
                <p style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '0.75rem', color: '#555', lineHeight: 1.6,
                }}>
                  {currentTab.description}
                </p>
              </div>

              {/* Metrics row */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
              }}>
                {currentTab.metrics.map((m, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '16px 16px',
                      borderRight: i < 2 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                    }}
                  >
                    <p style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '1.25rem', fontWeight: 700,
                      color: '#fff', letterSpacing: '-0.02em',
                      marginBottom: 3,
                    }}>
                      {m.value}
                    </p>
                    <p style={{
                      fontFamily: 'Inter, sans-serif',
                      fontSize: '0.6875rem', color: '#444',
                      lineHeight: 1.4,
                    }}>
                      {m.label}
                    </p>
                  </div>
                ))}
              </div>

              {/* Feed items */}
              <div style={{ padding: '8px 0' }}>
                {currentTab.mockupItems.map((item, i) => {
                  const s = STATUS_COLORS[item.status];
                  return (
                    <div
                      key={i}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '12px',
                        padding: '12px 18px',
                        borderBottom: i < currentTab.mockupItems.length - 1 ? '1px solid rgba(255,255,255,0.035)' : 'none',
                        transition: 'background 0.15s',
                        cursor: 'default',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.025)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      {/* Status dot */}
                      <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: s.dot, flexShrink: 0,
                        boxShadow: `0 0 6px ${s.dot}55`,
                      }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <p style={{
                          fontFamily: 'Inter, sans-serif',
                          fontSize: '0.8125rem', fontWeight: 500,
                          color: '#ddd',
                          letterSpacing: '-0.005em',
                          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                        }}>
                          {item.text}
                        </p>
                        <p style={{
                          fontFamily: 'Inter, sans-serif',
                          fontSize: '0.6875rem', color: '#444',
                          marginTop: 2,
                        }}>
                          {item.sub}
                        </p>
                      </div>
                      {/* Status badge */}
                      <span style={{
                        fontFamily: 'Inter, sans-serif',
                        fontSize: '0.625rem', fontWeight: 600,
                        letterSpacing: '0.07em', textTransform: 'uppercase',
                        color: s.dot,
                        background: s.bg,
                        border: `1px solid ${s.border}`,
                        borderRadius: 6,
                        padding: '2px 7px', flexShrink: 0,
                      }}>
                        {item.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Bottom label */}
            <p style={{
              fontFamily: 'Inter, sans-serif',
              fontSize: '0.75rem', color: '#444',
              textAlign: 'center', marginTop: '1rem',
              letterSpacing: '0.02em',
            }}>
              Live preview — real data from CYBERGUARD platform
            </p>
          </div>
        </div>
      </div>

      {/* Subtle bottom separator */}
      <div style={{
        position: 'absolute', bottom: 0, left: '10%', right: '10%', height: '1px',
        background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.06), transparent)',
      }} />
    </section>
  );
}
