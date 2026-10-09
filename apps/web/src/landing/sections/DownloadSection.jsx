import React, { useEffect, useRef, useState } from 'react';

/* ─────────────────────────────────────────────
   PLATFORM DATA
───────────────────────────────────────────── */
const PLATFORMS = [
  {
    id: 'ios',
    store: 'App Store',
    name: 'iOS',
    sub: 'iPhone & iPad',
    href: 'https://apps.apple.com/app/cyberguard',
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor">
        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
      </svg>
    ),
  },
  {
    id: 'android',
    store: 'Google Play',
    name: 'Android',
    sub: 'Phone & Tablet',
    href: 'https://play.google.com/store/apps/cyberguard',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor">
        <path d="M3.18 23.76c.37.21.8.22 1.19.04l11.15-6.43-2.47-2.47-9.87 8.86zM.5 1.28C.18 1.6 0 2.1 0 2.74v18.51c0 .64.18 1.14.5 1.47l.08.07 10.37-10.37v-.25L.58 1.21.5 1.28zM20.1 10.1l-2.96-1.71-2.77 2.77 2.77 2.77 2.97-1.72c.85-.49.85-1.28-.01-2.11zM4.37.19L15.52 6.63 13.06 9.1 3.18.24C3.58.05 4.01.07 4.37.19z"/>
      </svg>
    ),
  },
  {
    id: 'web',
    store: 'Web App',
    name: 'Browser',
    sub: 'No install needed',
    href: '/dashboard',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
      </svg>
    ),
  },
  {
    id: 'windows',
    store: 'Desktop App',
    name: 'Windows',
    sub: 'Windows 10 & 11',
    href: 'https://download.cyberguard.com/windows',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor">
        <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
      </svg>
    ),
  },
  {
    id: 'linux',
    store: 'Desktop App',
    name: 'Linux',
    sub: 'Debian & RPM',
    href: 'https://download.cyberguard.com/linux',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12.504 0C6.006 0 0 5.989 0 12.504c0 5.832 4.244 10.671 9.833 11.574.72.132.983-.31.983-.69v-2.41c-3.996.869-4.84-1.928-4.84-1.928-.655-1.667-1.598-2.11-1.598-2.11-1.304-.893.099-.876.099-.876 1.44.1 2.197 1.48 2.197 1.48 1.283 2.197 3.362 1.56 4.18 1.194.131-.928.501-1.56.912-1.919-3.189-.363-6.546-1.597-6.546-7.106 0-1.568.562-2.851 1.48-3.859-.148-.363-.641-1.824.14-3.804 0 0 1.204-.386 3.947 1.47a13.765 13.765 0 013.594-.484c1.222.006 2.451.165 3.594.484 2.741-1.856 3.944-1.47 3.944-1.47.783 1.98.29 3.441.142 3.804.92 1.008 1.48 2.291 1.48 3.859 0 5.521-3.364 6.74-6.564 7.094.517.443.977 1.319.977 2.659v3.942c0 .383.259.832.99.69C19.763 23.167 24 18.33 24 12.504 24 5.989 18.011 0 12.504 0z"/>
      </svg>
    ),
  },
  {
    id: 'docs',
    store: 'Documentation',
    name: 'Docs & API',
    sub: 'Developers',
    href: 'https://docs.cyberguard.com',
    icon: (
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
  },
];

/* ─────────────────────────────────────────────
   DOWNLOAD BUTTON CARD
───────────────────────────────────────────── */
function PlatformCard({ platform, visible, delay }) {
  const [hovered, setHovered] = useState(false);
  const isExternal = platform.href.startsWith('http');

  const handleClick = () => {
    if (isExternal) {
      window.open(platform.href, '_blank', 'noopener noreferrer');
    } else {
      window.location.href = platform.href;
    }
  };

  return (
    <button
      onClick={handleClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        background: hovered ? '#1A1A1A' : '#141414',
        border: `1px solid ${hovered ? 'rgba(255,255,255,0.14)' : 'rgba(255,255,255,0.07)'}`,
        borderRadius: 14,
        padding: '18px 22px',
        cursor: 'pointer',
        width: '100%',
        textAlign: 'left',
        position: 'relative',
        overflow: 'hidden',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateY(0)' : 'translateY(20px)',
        transition: `opacity 0.55s ease ${delay}ms, transform 0.55s ease ${delay}ms, background 0.2s ease, border-color 0.2s ease`,
      }}
    >
      {/* Subtle hover glow */}
      <div style={{
        position: 'absolute',
        inset: 0,
        background: 'radial-gradient(circle at 30% 50%, rgba(255,255,255,0.025) 0%, transparent 70%)',
        opacity: hovered ? 1 : 0,
        transition: 'opacity 0.25s ease',
        pointerEvents: 'none',
      }} />

      {/* Icon container */}
      <div style={{
        width: 48, height: 48,
        borderRadius: 12,
        background: hovered ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${hovered ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.06)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
        color: hovered ? '#fff' : '#888',
        transition: 'background 0.2s, border-color 0.2s, color 0.2s',
      }}>
        {platform.icon}
      </div>

      {/* Text stack */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontSize: '0.6875rem',
          fontWeight: 500,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: '#444',
          marginBottom: 3,
          lineHeight: 1,
        }}>
          {platform.store}
        </p>
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontSize: '0.9375rem',
          fontWeight: 700,
          color: hovered ? '#fff' : '#ccc',
          letterSpacing: '-0.01em',
          lineHeight: 1,
          marginBottom: 3,
          transition: 'color 0.2s',
        }}>
          {platform.name}
        </p>
        <p style={{
          fontFamily: 'Inter, sans-serif',
          fontSize: '0.75rem',
          color: '#3A3A3A',
          lineHeight: 1,
          transition: 'color 0.2s',
        }}>
          {platform.sub}
        </p>
      </div>

      {/* Arrow */}
      <svg
        width="14" height="14"
        viewBox="0 0 24 24" fill="none"
        stroke={hovered ? '#fff' : '#333'}
        strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
        style={{
          flexShrink: 0,
          transform: hovered ? 'translate(2px, -2px)' : 'translate(0,0)',
          transition: 'transform 0.2s ease, stroke 0.2s ease',
        }}
      >
        <path d="M7 17L17 7M17 7H7M17 7v10" />
      </svg>
    </button>
  );
}

/* ─────────────────────────────────────────────
   MAIN SECTION
───────────────────────────────────────────── */
export default function DownloadSection() {
  const [visible, setVisible] = useState(false);
  const sectionRef = useRef(null);
  const triggered  = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !triggered.current) {
          triggered.current = true;
          setVisible(true);
        }
      },
      { threshold: 0.1 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      id="download"
      ref={sectionRef}
      style={{
        position: 'relative',
        background: '#0A0A0A',
        paddingTop: '100px',
        paddingBottom: '100px',
        overflow: 'hidden',
      }}
    >
      {/* Landscape bg — very subtle */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'url(/hero-bg.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center 65%',
        opacity: 0.08,
        filter: 'saturate(0.3)',
        pointerEvents: 'none',
      }} />
      {/* Gradient mask */}
      <div style={{
        position: 'absolute', inset: 0,
        background: 'linear-gradient(to bottom, #0A0A0A 0%, rgba(10,10,10,0.6) 50%, #0A0A0A 100%)',
        pointerEvents: 'none',
      }} />

      {/* Top separator */}
      <div style={{
        position: 'absolute', top: 0, left: '10%', right: '10%', height: '1px',
        background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.06), transparent)',
      }} />

      <div style={{
        position: 'relative', zIndex: 1,
        maxWidth: '1440px',
        marginInline: 'auto',
        paddingInline: 'clamp(1.5rem, 5vw, 6rem)',
      }}>

        {/* ── Section header — centered ── */}
        <div style={{ textAlign: 'center', marginBottom: '64px' }}>
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
            Get the app
          </div>

          <h2 style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
            fontWeight: 650,
            fontSize: 'clamp(1.75rem, 2.8vw, 2.35rem)',
            lineHeight: 1.22,
            letterSpacing: '-0.025em',
            color: '#fff',
            marginBottom: '1.25rem',
          }}>
            Get CYBERGUARD Today
          </h2>
          <p style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 'clamp(1rem, 1.8vw, 1.125rem)',
            lineHeight: 1.7,
            color: '#666',
            maxWidth: '460px',
            marginInline: 'auto',
          }}>
            Available on iOS, Android, Web, and Desktop.
            Free to download and use.
          </p>
        </div>

        {/* ── Platform grid ── */}
        <div style={{
          maxWidth: '860px',
          marginInline: 'auto',
        }}>
          {/* Row 1 — 3 platforms */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 240px), 1fr))',
            gap: '12px',
            marginBottom: '12px',
          }}>
            {PLATFORMS.slice(0, 3).map((p, i) => (
              <PlatformCard
                key={p.id}
                platform={p}
                visible={visible}
                delay={i * 80}
              />
            ))}
          </div>

          {/* Row 2 — 3 platforms */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 240px), 1fr))',
            gap: '12px',
          }}>
            {PLATFORMS.slice(3).map((p, i) => (
              <PlatformCard
                key={p.id}
                platform={p}
                visible={visible}
                delay={(i + 3) * 80}
              />
            ))}
          </div>
        </div>

        {/* ── Trust strip ── */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '24px',
          marginTop: '48px',
          paddingTop: '40px',
          borderTop: '1px solid rgba(255,255,255,0.05)',
          maxWidth: '860px',
          marginInline: 'auto',
        }}>
          {[
            {
              icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/><path d="M9 12l2 2 4-4"/></svg>,
              text: 'Free forever plan',
            },
            {
              icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>,
              text: 'No credit card required',
            },
            {
              icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
              text: 'Setup in under 60 seconds',
            },
            {
              icon: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 10.8a19.79 19.79 0 01-3.07-8.7A2 2 0 012 0h3a2 2 0 012 1.72c.13 1 .37 1.97.72 2.9a2 2 0 01-.45 2.11L6.09 7.91a16 16 0 006 6l1.18-1.18a2 2 0 012.11-.45c.93.35 1.9.59 2.9.72A2 2 0 0122 14.92v2z"/></svg>,
              text: '24/7 threat monitoring',
            },
          ].map((item, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              fontFamily: 'Inter, sans-serif',
              fontSize: '0.8125rem',
              color: '#555',
            }}>
              <span style={{ color: '#333', flexShrink: 0 }}>{item.icon}</span>
              {item.text}
            </div>
          ))}
        </div>

        {/* ── Version note ── */}
        <p style={{
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: '0.6875rem',
          color: '#2E2E2E',
          textAlign: 'center',
          marginTop: '1.5rem',
          letterSpacing: '0.06em',
        }}>
          v2.4.1 — Released Oct 2026 · MIT Licensed · Open Source
        </p>
      </div>

      {/* Bottom separator */}
      <div style={{
        position: 'absolute', bottom: 0, left: '10%', right: '10%', height: '1px',
        background: 'linear-gradient(to right, transparent, rgba(255,255,255,0.06), transparent)',
      }} />
    </section>
  );
}
