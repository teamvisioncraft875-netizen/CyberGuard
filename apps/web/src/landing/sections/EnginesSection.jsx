import React, { useEffect, useRef, useState } from 'react';

/* ─────────────────────────────────────────────
   ENGINE DATA
───────────────────────────────────────────── */
const ENGINES = [
  {
    id: 'phishing',
    label: 'Engine 01',
    title: 'Phishing Detection',
    desc: 'Identifies fraudulent emails, messages, and pages using NLP classifiers trained on 12M+ phishing samples.',
    stat: { val: '98.4%', label: 'Detection rate' },
    tag: 'NLP · BERT',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
        <polyline points="22,6 12,13 2,6" />
      </svg>
    ),
  },
  {
    id: 'url',
    label: 'Engine 02',
    title: 'URL Analysis',
    desc: 'Real-time analysis of links and domains against threat intelligence feeds, WHOIS data, and reputation scores.',
    stat: { val: '< 800ms', label: 'Avg scan time' },
    tag: 'ML · OSINT',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" />
      </svg>
    ),
  },
  {
    id: 'deepfake',
    label: 'Engine 03',
    title: 'Deepfake Detection',
    desc: 'Vision transformer models identify AI-generated images, videos, and audio with frame-level analysis.',
    stat: { val: '96.1%', label: 'Accuracy on DF-40' },
    tag: 'ViT · CNN',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M23 7l-7 5 7 5V7z" />
        <rect x="1" y="5" width="15" height="14" rx="2" ry="2" />
        <path d="M8 10l2 2-2 2" />
      </svg>
    ),
  },
  {
    id: 'anomaly',
    label: 'Engine 04',
    title: 'Login Anomaly',
    desc: 'Detects suspicious account activity — impossible travel, credential stuffing, and behavioural deviations.',
    stat: { val: '0.3%', label: 'False positive rate' },
    tag: 'Isolation Forest',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
        <line x1="12" y1="16" x2="12" y2="16" strokeWidth="2.5" />
      </svg>
    ),
  },
  {
    id: 'secrets',
    label: 'Engine 05',
    title: 'Secret Exposure',
    desc: 'Scans messages, screenshots, and files for leaked API keys, passwords, tokens, and PII using regex + ML.',
    stat: { val: '40+', label: 'Secret patterns' },
    tag: 'Regex · ML',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
      </svg>
    ),
  },
  {
    id: 'ddos',
    label: 'Engine 06',
    title: 'DDoS Detection',
    desc: 'Traffic fingerprinting and rate analysis identifies volumetric, protocol, and application-layer attacks.',
    stat: { val: '10Gbps', label: 'Traffic analysed' },
    tag: 'Statistical · DL',
    icon: (color) => (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="2" />
        <path d="M12 2a10 10 0 100 20A10 10 0 0012 2z" />
        <path d="M12 6v2M12 16v2M6 12H4M20 12h-2M7.76 7.76L6.34 6.34M17.66 17.66l-1.42-1.42M7.76 16.24l-1.42 1.42M17.66 6.34l-1.42 1.42" />
      </svg>
    ),
  },
];

/* ─────────────────────────────────────────────
   ENGINE CARD
───────────────────────────────────────────── */
function EngineCard({ engine, visible, delay }) {
  const [hovered, setHovered] = useState(false);

  const ACCENT = '#00D9FF';

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? '#1C1C1C' : '#161616',
        border: `1px solid ${hovered ? 'rgba(0,217,255,0.18)' : 'rgba(255,255,255,0.07)'}`,
        borderRadius: 14,
        padding: '28px 24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '0',
        cursor: 'default',
        position: 'relative',
        overflow: 'hidden',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(24px)',
        transition: `opacity 0.6s ease ${delay}ms, transform 0.6s ease ${delay}ms, background 0.2s ease, border-color 0.2s ease`,
      }}
    >
      {/* Subtle top-left glow on hover */}
      <div style={{
        position: 'absolute',
        top: -40, left: -40,
        width: 120, height: 120,
        borderRadius: '50%',
        background: 'rgba(0,217,255,0.05)',
        opacity: hovered ? 1 : 0,
        transition: 'opacity 0.3s ease',
        pointerEvents: 'none',
      }} />

      {/* ── Top row: icon + label ── */}
      <div style={{
        display: 'flex', alignItems: 'flex-start',
        justifyContent: 'space-between',
        marginBottom: '20px',
      }}>
        {/* Icon box */}
        <div style={{
          width: 44, height: 44,
          borderRadius: 10,
          background: hovered ? 'rgba(0,217,255,0.1)' : 'rgba(255,255,255,0.04)',
          border: `1px solid ${hovered ? 'rgba(0,217,255,0.2)' : 'rgba(255,255,255,0.07)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
          transition: 'background 0.25s ease, border-color 0.25s ease',
        }}>
          {engine.icon(hovered ? ACCENT : '#555')}
        </div>

        {/* Engine label */}
        <span style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '0.625rem',
          fontWeight: 600,
          letterSpacing: '0.1em',
          color: '#333',
          textTransform: 'uppercase',
        }}>
          {engine.label}
        </span>
      </div>

      {/* ── Title ── */}
      <h3 style={{
        fontFamily: 'Inter, sans-serif',
        fontSize: '1rem',
        fontWeight: 700,
        color: hovered ? '#fff' : '#E0E0E0',
        letterSpacing: '-0.02em',
        marginBottom: '8px',
        transition: 'color 0.2s ease',
      }}>
        {engine.title}
      </h3>

      {/* ── Description ── */}
      <p style={{
        fontFamily: 'Inter, sans-serif',
        fontSize: '0.8125rem',
        fontWeight: 400,
        color: '#555',
        lineHeight: 1.65,
        flex: 1,
        marginBottom: '20px',
      }}>
        {engine.desc}
      </p>

      {/* ── Bottom row: stat + tech tag ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingTop: '16px',
        borderTop: '1px solid rgba(255,255,255,0.05)',
        gap: '8px',
      }}>
        {/* Stat */}
        <div>
          <span style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: '0.9375rem',
            fontWeight: 700,
            color: hovered ? '#fff' : '#ccc',
            letterSpacing: '-0.02em',
            display: 'block',
            lineHeight: 1,
            marginBottom: 3,
            transition: 'color 0.2s ease',
          }}>
            {engine.stat.val}
          </span>
          <span style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: '0.6875rem',
            color: '#444',
          }}>
            {engine.stat.label}
          </span>
        </div>

        {/* Tech tag */}
        <span style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '0.625rem',
          fontWeight: 500,
          color: hovered ? '#00D9FF' : '#3A3A3A',
          background: hovered ? 'rgba(0,217,255,0.08)' : 'rgba(255,255,255,0.03)',
          border: `1px solid ${hovered ? 'rgba(0,217,255,0.15)' : 'rgba(255,255,255,0.06)'}`,
          borderRadius: 6,
          padding: '4px 8px',
          letterSpacing: '0.06em',
          whiteSpace: 'nowrap',
          transition: 'color 0.2s ease, background 0.2s ease, border-color 0.2s ease',
        }}>
          {engine.tag}
        </span>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   MAIN SECTION
───────────────────────────────────────────── */
export default function EnginesSection() {
  const [visibleCards, setVisibleCards] = useState(new Set());
  const sectionRef = useRef(null);
  const cardRefs   = useRef([]);
  const triggered  = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !triggered.current) {
          triggered.current = true;
          // Stagger cards into view
          ENGINES.forEach((_, i) => {
            setTimeout(() => {
              setVisibleCards(prev => new Set([...prev, i]));
            }, i * 100);
          });
        }
      },
      { threshold: 0.1 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      id="engines"
      ref={sectionRef}
      style={{
        background: '#0A0A0A',
        paddingTop: '100px',
        paddingBottom: '100px',
        position: 'relative',
      }}
    >
      {/* Top separator */}
      <div style={{
        position: 'absolute', top: 0, left: '10%', right: '10%', height: '1px',
        background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.06), transparent)',
      }} />

      <div style={{
        maxWidth: '1440px',
        marginInline: 'auto',
        paddingInline: 'clamp(1.5rem, 5vw, 6rem)',
      }}>

        {/* ── Section header ── */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: '2rem',
          marginBottom: '56px',
        }}>
          <div>
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
              Detection Engines
            </div>

            <h2 style={{
              fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
              fontWeight: 650,
              fontSize: 'clamp(1.75rem, 2.8vw, 2.35rem)',
              lineHeight: 1.22,
              letterSpacing: '-0.025em',
              color: '#fff',
              marginBottom: '1rem',
            }}>
              6 Production Detection Engines.
            </h2>
            <p style={{
              fontFamily: 'Inter, sans-serif',
              fontSize: 'clamp(1rem, 1.8vw, 1.1rem)',
              lineHeight: 1.7,
              color: '#666',
              maxWidth: '480px',
            }}>
              Comprehensive threat detection across all attack surfaces —
              running in parallel, every second.
            </p>
          </div>

          {/* Right: aggregate stat */}
          <div style={{
            display: 'flex',
            gap: '2rem',
            flexShrink: 0,
          }}>
            {[
              { val: '12M+', label: 'Training samples' },
              { val: '6',    label: 'Active engines' },
              { val: '1.2s', label: 'End-to-end latency' },
            ].map((s, i) => (
              <div key={i} style={{ textAlign: 'center' }}>
                <p style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: '1.5rem', fontWeight: 800,
                  color: '#fff', letterSpacing: '-0.03em',
                  lineHeight: 1, marginBottom: 4,
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

        {/* ── Engine cards grid ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(min(100%, 320px), 1fr))',
          gap: '1px',
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid rgba(255,255,255,0.04)',
          borderRadius: 16,
          overflow: 'hidden',
        }}>
          {ENGINES.map((engine, i) => (
            <div key={engine.id} ref={el => cardRefs.current[i] = el} style={{ background: '#0A0A0A' }}>
              <EngineCard
                engine={engine}
                visible={visibleCards.has(i)}
                delay={0}
              />
            </div>
          ))}
        </div>

        {/* ── Bottom note ── */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          marginTop: '2.5rem',
          paddingTop: '2rem',
          borderTop: '1px solid rgba(255,255,255,0.05)',
        }}>
          <p style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: '0.8125rem',
            color: '#444',
          }}>
            All engines run concurrently — zero performance penalty.
          </p>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {['Open-source models', 'On-device inference', 'GDPR compliant', 'SOC 2 Type II'].map(tag => (
              <span key={tag} style={{
                fontFamily: 'Inter, sans-serif',
                fontSize: '0.6875rem', fontWeight: 500,
                color: '#444',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderRadius: 6,
                padding: '4px 10px',
              }}>
                {tag}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom separator */}
      <div style={{
        position: 'absolute', bottom: 0, left: '10%', right: '10%', height: '1px',
        background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.06), transparent)',
      }} />
    </section>
  );
}
