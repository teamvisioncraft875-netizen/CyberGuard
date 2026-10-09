import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';

const NAV_LINKS = [
  { label: 'About',    href: '#about' },
  { label: 'Features', href: '#features' },
  { label: 'Engines',  href: '#engines' },
  { label: 'Pricing',  href: '#pricing' },
  { label: 'Download', href: '#download' },
  { label: 'FAQ',      href: '#faq' },
];

export default function LandingNav() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();
  const navRef = useRef(null);

  /* ── Scroll state ── */
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  /* ── Close mobile menu on outside click ── */
  useEffect(() => {
    if (!mobileOpen) return;
    const handler = (e) => {
      if (navRef.current && !navRef.current.contains(e.target)) {
        setMobileOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [mobileOpen]);

  /* ── Smooth scroll to anchor ── */
  const scrollTo = (href) => {
    setMobileOpen(false);
    if (href.startsWith('#')) {
      const el = document.querySelector(href);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <nav
      ref={navRef}
      style={{
        position: 'fixed',
        top: 0, left: 0, right: 0,
        zIndex: 200,
        height: '72px',
        background: scrolled
          ? 'rgba(32, 38, 44, 0.94)'
          : 'transparent',
        backdropFilter: scrolled ? 'blur(16px) saturate(160%)' : 'none',
        WebkitBackdropFilter: scrolled ? 'blur(16px) saturate(160%)' : 'none',
        borderBottom: scrolled
          ? '1px solid rgba(255,255,255,0.07)'
          : '1px solid transparent',
        transition: 'background 0.35s ease, border-color 0.35s ease, backdrop-filter 0.35s ease',
      }}
    >
      <div style={{
        maxWidth: '1440px',
        marginInline: 'auto',
        paddingInline: 'clamp(1.5rem, 4vw, 4rem)',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '2rem',
      }}>

        {/* ── Logo ── */}
        <Link
          to="/"
          style={{
            display: 'flex', alignItems: 'center', gap: '10px',
            textDecoration: 'none', flexShrink: 0,
          }}
        >
          {/* Shield icon mark */}
          <div style={{
            width: 30, height: 30,
            background: '#fff',
            borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
              <path
                d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"
                fill="#0F0F0F"
              />
              <path
                d="M9 12l2 2 4-4"
                stroke="#fff"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <span style={{
            fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
            fontWeight: 650,
            fontSize: '1.0625rem',
            color: '#fff',
            letterSpacing: '-0.02em',
          }}>
            CyberGuard.
          </span>
        </Link>

        {/* ── Desktop Nav Links ── */}
        <ul style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          listStyle: 'none', margin: 0, padding: 0,
        }}
          className="lp-nav-desktop"
        >
          {NAV_LINKS.map((link) => (
            <li key={link.label}>
              <button
                onClick={() => scrollTo(link.href)}
                style={{
                  fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  color: '#A1A1A6',
                  background: 'none', border: 'none',
                  cursor: 'pointer',
                  padding: '6px 14px',
                  borderRadius: 8,
                  transition: 'color 0.15s ease',
                }}
                onMouseEnter={e => { e.currentTarget.style.color = '#fff'; }}
                onMouseLeave={e => { e.currentTarget.style.color = '#A1A1A6'; }}
              >
                {link.label}
              </button>
            </li>
          ))}
        </ul>

        {/* ── Right: CTA Buttons ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexShrink: 0 }}>
          {/* Login — clean text button */}
          <button
            onClick={() => navigate('/login')}
            className="lp-nav-login-btn"
            style={{
              fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
              fontSize: '0.875rem',
              fontWeight: 500,
              color: '#A1A1A6',
              background: 'transparent',
              border: 'none',
              padding: '6px 10px',
              cursor: 'pointer',
              transition: 'color 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = '#fff'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#A1A1A6'; }}
          >
            Login
          </button>

          {/* Get started — dark translucent pill matching Fora */}
          <button
            onClick={() => scrollTo('#download')}
            className="lp-nav-download-btn"
            style={{
              fontFamily: '"Plus Jakarta Sans", "Inter", sans-serif',
              fontSize: '0.875rem',
              fontWeight: 500,
              color: '#FFFFFF',
              background: 'rgba(255, 255, 255, 0.1)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              borderRadius: 9999,
              padding: '8px 20px',
              cursor: 'pointer',
              backdropFilter: 'blur(8px)',
              transition: 'background 0.2s, border-color 0.2s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.18)';
              e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.28)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)';
              e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.15)';
            }}
          >
            Get started
          </button>

          {/* ── Mobile hamburger ── */}
          <button
            className="lp-hamburger"
            onClick={() => setMobileOpen(v => !v)}
            aria-label="Toggle menu"
            style={{
              display: 'none',
              background: 'none', border: 'none', cursor: 'pointer',
              padding: 6,
              color: '#fff',
            }}
          >
            {mobileOpen ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 12h18M3 6h18M3 18h18" />
              </svg>
            )}
          </button>
        </div>
      </div>

      {/* ── Mobile Dropdown ── */}
      {mobileOpen && (
        <div style={{
          position: 'absolute', top: '72px', left: 0, right: 0,
          background: 'rgba(12, 12, 12, 0.98)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid rgba(255,255,255,0.07)',
          padding: '12px 0 20px',
          display: 'flex', flexDirection: 'column', gap: 2,
        }}>
          {NAV_LINKS.map((link) => (
            <button
              key={link.label}
              onClick={() => scrollTo(link.href)}
              style={{
                fontFamily: 'Inter, sans-serif',
                fontSize: '0.9375rem',
                fontWeight: 500,
                color: '#bbb',
                background: 'none', border: 'none',
                textAlign: 'left',
                padding: '12px 24px',
                cursor: 'pointer',
                transition: 'color 0.15s',
              }}
              onMouseEnter={e => e.currentTarget.style.color = '#fff'}
              onMouseLeave={e => e.currentTarget.style.color = '#bbb'}
            >
              {link.label}
            </button>
          ))}
          <div style={{ margin: '8px 24px 0', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <button
              onClick={() => navigate('/login')}
              style={{
                fontFamily: 'Inter, sans-serif', fontSize: '0.9375rem', fontWeight: 500,
                color: '#ccc', background: 'transparent',
                border: '1px solid rgba(255,255,255,0.15)', borderRadius: 24,
                padding: '12px 0', cursor: 'pointer', width: '100%',
              }}
            >
              Login
            </button>
            <button
              onClick={() => scrollTo('#download')}
              style={{
                fontFamily: 'Inter, sans-serif', fontSize: '0.9375rem', fontWeight: 600,
                color: '#0F0F0F', background: '#fff',
                border: 'none', borderRadius: 24,
                padding: '12px 0', cursor: 'pointer', width: '100%',
              }}
            >
              Get started
            </button>
          </div>
        </div>
      )}

      {/* ── Responsive CSS ── */}
      <style>{`
        @media (max-width: 767px) {
          .lp-nav-desktop { display: none !important; }
          .lp-nav-login-btn { display: none !important; }
          .lp-nav-download-btn { display: none !important; }
          .lp-hamburger { display: flex !important; }
        }
      `}</style>
    </nav>
  );
}
