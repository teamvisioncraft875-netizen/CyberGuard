import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { gsap } from 'gsap';

export default function HeroSection() {
  const navigate = useNavigate();

  /* ── Refs for GSAP ── */
  const badgeRef    = useRef(null);
  const headlineRef = useRef(null);
  const subRef      = useRef(null);
  const ctaRef      = useRef(null);
  const mockupRef   = useRef(null);

  /* ── GSAP entrance animation ── */
  useEffect(() => {
    const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });

    // Start elements invisible
    gsap.set([badgeRef.current, headlineRef.current, subRef.current, ctaRef.current, mockupRef.current], {
      opacity: 0,
      y: 24,
    });

    // Staggered entrance
    tl.to(badgeRef.current,    { opacity: 1, y: 0, duration: 0.6 },  0.15)
      .to(headlineRef.current, { opacity: 1, y: 0, duration: 0.75 }, 0.3)
      .to(subRef.current,      { opacity: 1, y: 0, duration: 0.65 }, 0.48)
      .to(ctaRef.current,      { opacity: 1, y: 0, duration: 0.6 },  0.64)
      .to(mockupRef.current,   { opacity: 1, y: 0, duration: 0.8 },  0.78);

    return () => tl.kill();
  }, []);

  const scrollTo = (id) => {
    const el = document.querySelector(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <section
      id="hero"
      style={{
        position: 'relative',
        width: '100%',
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'flex-start',
        /* ── Exact mathematical Fora dusk-to-slate gradient fading seamlessly into black (#0F0F0F) ── */
        background: 'linear-gradient(180deg, #272F35 0%, #2A3339 12%, #2F373E 24%, #363F45 36%, #41464B 48%, #524E52 58%, #665A5E 68%, #796568 76%, #856B6D 82%, #685759 88%, #3A3236 93%, #1F1B1E 97%, #0F0F0F 100%)',
        backgroundColor: '#0F0F0F',
        paddingBottom: 'clamp(60px, 8vh, 100px)',
      }}
    >
      {/* ── Seamless gradient fade-to-black bottom blend into next section ── */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: '240px',
          background: 'linear-gradient(to bottom, rgba(15, 15, 15, 0) 0%, rgba(15, 15, 15, 0.45) 45%, rgba(15, 15, 15, 0.88) 80%, #0F0F0F 100%)',
          pointerEvents: 'none',
          zIndex: 5,
        }}
      />

      {/* ── Content Container ── */}
      <div
        style={{
          position: 'relative',
          zIndex: 10,
          width: '100%',
          maxWidth: '1280px',
          marginInline: 'auto',
          paddingInline: 'clamp(1.5rem, 5vw, 4rem)',
          paddingTop: 'clamp(120px, 18vh, 160px)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
        }}
      >
        {/* ── Overline Pill Badge ── */}
        <div
          ref={badgeRef}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontFamily: '"Plus Jakarta Sans", "Inter", -apple-system, sans-serif',
            fontSize: '0.875rem',
            fontWeight: 500,
            color: '#D1D1D6',
            background: 'rgba(255, 255, 255, 0.06)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '9999px',
            padding: '7px 20px',
            marginBottom: '1.75rem',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            boxShadow: '0 2px 10px rgba(0,0,0,0.15)',
          }}
        >
          <span>AI-powered cyber defense platform</span>
        </div>

        {/* ── Headline matching Fora's typography & weight ── */}
        <h1
          ref={headlineRef}
          style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", -apple-system, sans-serif',
            fontWeight: 550,
            fontSize: 'clamp(2.1rem, 4.2vw, 3.4rem)',
            lineHeight: 1.18,
            letterSpacing: '-0.025em',
            color: '#FFFFFF',
            maxWidth: '820px',
            marginBottom: '1.5rem',
          }}
        >
          AI-Powered Cyber Defense
          <br />
          deserves its own platform.
        </h1>

        {/* ── Sub-headline ── */}
        <p
          ref={subRef}
          style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", -apple-system, sans-serif',
            fontWeight: 400,
            fontSize: 'clamp(1rem, 2vw, 1.15rem)',
            lineHeight: 1.65,
            color: '#A1A1A8',
            maxWidth: '580px',
            marginBottom: '2.5rem',
          }}
        >
          Threats detected in seconds. Responses automated in minutes.
          All in one unified platform built for the modern threat landscape.
        </p>

        {/* ── CTA Action (Clean Fora-style pill button) ── */}
        <div
          ref={ctaRef}
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '14px',
            marginBottom: '4.5rem',
          }}
        >
          {/* Primary Button */}
          <button
            type="button"
            onClick={() => scrollTo('#download')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontFamily: '"Plus Jakarta Sans", "Inter", -apple-system, sans-serif',
              fontSize: '0.9375rem',
              fontWeight: 500,
              color: '#141416',
              background: '#E6E6EA',
              border: 'none',
              borderRadius: '9999px',
              height: '48px',
              padding: '0 30px',
              cursor: 'pointer',
              transition: 'background 0.2s ease, transform 0.15s ease, box-shadow 0.2s ease',
              letterSpacing: '-0.01em',
              boxShadow: '0 4px 18px rgba(0,0,0,0.3)',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = '#FFFFFF';
              e.currentTarget.style.transform = 'scale(1.02)';
              e.currentTarget.style.boxShadow = '0 6px 24px rgba(255,255,255,0.2)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = '#E6E6EA';
              e.currentTarget.style.transform = 'scale(1)';
              e.currentTarget.style.boxShadow = '0 4px 18px rgba(0,0,0,0.3)';
            }}
          >
            Get started free
          </button>

          {/* Secondary Outline Button */}
          <button
            type="button"
            onClick={() => scrollTo('#how-it-works')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              fontFamily: '"Plus Jakarta Sans", "Inter", -apple-system, sans-serif',
              fontSize: '0.9375rem',
              fontWeight: 500,
              color: '#D1D1D6',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '9999px',
              height: '48px',
              padding: '0 24px',
              cursor: 'pointer',
              backdropFilter: 'blur(8px)',
              WebkitBackdropFilter: 'blur(8px)',
              transition: 'background 0.2s, color 0.2s, border-color 0.2s, transform 0.15s',
              letterSpacing: '-0.01em',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.09)';
              e.currentTarget.style.color = '#FFFFFF';
              e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.22)';
              e.currentTarget.style.transform = 'scale(1.02)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
              e.currentTarget.style.color = '#D1D1D6';
              e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)';
              e.currentTarget.style.transform = 'scale(1)';
            }}
          >
            Explore detection engines
          </button>
        </div>

        {/* ── Product Peek Preview Window (Full, finished frame matching Fora app card) ── */}
        <div
          ref={mockupRef}
          style={{
            width: '100%',
            maxWidth: '1020px',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            background: 'rgba(18, 19, 23, 0.88)',
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.75), 0 0 50px rgba(0, 217, 255, 0.04)',
            overflow: 'hidden',
            padding: '16px 20px 20px',
          }}
        >
          {/* Mockup Browser Window Header */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingBottom: '14px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
            }}
          >
            {/* Window dots */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#EF4444' }} />
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#F59E0B' }} />
              <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#10B981' }} />
            </div>

            {/* Address / Search capsule */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '8px',
                padding: '4px 14px',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                color: '#8A8A93',
              }}
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
              <span>cyberguard.app/telemetry/live-monitor</span>
            </div>

            {/* Live indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#00D9FF' }} />
              <span style={{ fontSize: '0.6875rem', color: '#9CA3AF', fontFamily: 'sans-serif', fontWeight: 500 }}>
                6 Engines Active
              </span>
            </div>
          </div>

          {/* Mockup Preview Content */}
          <div
            style={{
              paddingTop: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
            }}
          >
            {/* Top Stat Cards */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '12px',
                alignItems: 'start',
              }}
            >
              {/* Live Metric 1 */}
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '10px', padding: '14px 16px', textAlign: 'left' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.6875rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Threat Telemetry</span>
                  <span style={{ fontSize: '0.625rem', color: '#10B981', background: 'rgba(16,185,129,0.1)', padding: '2px 6px', borderRadius: '4px' }}>Optimal</span>
                </div>
                <div style={{ fontSize: '1.125rem', fontWeight: 600, color: '#FFF' }}>Zero Infiltrations</div>
              </div>

              {/* Live Metric 2 */}
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '10px', padding: '14px 16px', textAlign: 'left' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.6875rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Deepfake Engine</span>
                  <span style={{ fontSize: '0.625rem', color: '#00D9FF', background: 'rgba(0,217,255,0.1)', padding: '2px 6px', borderRadius: '4px' }}>99.8% Conf</span>
                </div>
                <div style={{ fontSize: '1.125rem', fontWeight: 600, color: '#00D9FF' }}>Authentic Verified</div>
              </div>

              {/* Live Metric 3 */}
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '10px', padding: '14px 16px', textAlign: 'left' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.6875rem', color: '#888', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Average Response</span>
                  <span style={{ fontSize: '0.625rem', color: '#22C55E', background: 'rgba(34,197,94,0.1)', padding: '2px 6px', borderRadius: '4px' }}>On-Device</span>
                </div>
                <div style={{ fontSize: '1.125rem', fontWeight: 600, color: '#22C55E' }}>12ms latency</div>
              </div>
            </div>

            {/* Bottom Live Activity Feed Strip */}
            <div
              style={{
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: '10px',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                fontSize: '0.75rem',
                color: '#71717A',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#22C55E' }} />
                <span style={{ color: '#D4D4D8', fontFamily: 'monospace' }}>[SYSTEM]</span>
                <span>Real-time threat monitoring active across all endpoints</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontFamily: 'monospace', fontSize: '0.6875rem' }}>
                <span style={{ color: '#9CA3AF' }}>ENGINES: 6/6 OK</span>
                <span style={{ color: '#00D9FF' }}>ENCRYPTION: AES-GCM</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
