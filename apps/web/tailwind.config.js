import tailwindcssAnimate from 'tailwindcss-animate';

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{js,jsx}',
  ],
  theme: {
    container: {
      center: true,
      padding: '2rem',
      screens: {
        '2xl': '1400px',
      },
    },
    extend: {
      colors: {
        // Shadcn UI standard HSL variable mapping
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
          container: 'hsl(var(--primary))',
          fixed: 'hsl(var(--primary))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
          fixed: 'hsl(var(--secondary))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        error: {
          DEFAULT: 'hsl(var(--destructive))',
          container: 'hsl(var(--destructive) / 0.15)',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },

        // Semantic Surface Tiers (Light & Dark dynamic)
        surface: {
          DEFAULT: 'hsl(var(--background))',
          lowest: 'hsl(var(--surface-lowest))',
          low: 'hsl(var(--surface-low))',
          container: 'hsl(var(--surface-container))',
          high: 'hsl(var(--surface-high))',
          highest: 'hsl(var(--surface-highest))',
        },

        'on-surface': {
          DEFAULT: 'hsl(var(--text-primary))',
          variant: 'hsl(var(--text-secondary))',
        },
        outline: {
          DEFAULT: 'hsl(var(--text-muted))',
          variant: 'hsl(var(--border))',
        },

        // Legacy Cyber Tokens mapped to theme variables
        cyber: {
          dark: 'hsl(var(--surface-lowest))',
          panel: 'hsl(var(--surface-low))',
          card: 'hsl(var(--card))',
          border: 'hsl(var(--border))',
          borderGlow: 'hsl(var(--primary))',
          accent: 'hsl(var(--primary))',
          accentHover: 'hsl(var(--primary))',
          danger: 'hsl(var(--destructive))',
          warning: 'hsl(var(--risk-medium-text))',
          success: 'hsl(var(--risk-safe-text))',
          muted: 'hsl(var(--text-muted))',
        },

        // Risk Level Tokens (Light & Dark calibrated)
        risk: {
          safe: 'hsl(var(--risk-safe-text))',
          low: 'hsl(var(--risk-low-text))',
          medium: 'hsl(var(--risk-medium-text))',
          high: 'hsl(var(--risk-high-text))',
          critical: 'hsl(var(--risk-critical-text))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      fontFamily: {
        headline: ['"Plus Jakarta Sans"', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      // Landing page extended font sizes
      fontSize: {
        'lp-xs':  ['0.75rem',  { lineHeight: '1rem' }],
        'lp-sm':  ['0.875rem', { lineHeight: '1.25rem' }],
        'lp-base':['1rem',     { lineHeight: '1.6' }],
        'lp-lg':  ['1.125rem', { lineHeight: '1.75' }],
        'lp-xl':  ['1.25rem',  { lineHeight: '1.75rem' }],
        'lp-2xl': ['1.5rem',   { lineHeight: '1.15' }],
        'lp-3xl': ['1.875rem', { lineHeight: '1.15' }],
        'lp-4xl': ['2.25rem',  { lineHeight: '1.1' }],
        'lp-5xl': ['3rem',     { lineHeight: '1.05' }],
        'lp-6xl': ['3.75rem',  { lineHeight: '1' }],
        'lp-7xl': ['4.5rem',   { lineHeight: '1' }],
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
        // Landing page animations
        'lp-fade-up': {
          from: { opacity: '0', transform: 'translateY(24px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'lp-fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'lp-slide-down': {
          from: { opacity: '0', transform: 'translateY(-8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
        'lp-fade-up':   'lp-fade-up 0.6s cubic-bezier(0,0,0.2,1) forwards',
        'lp-fade-in':   'lp-fade-in 0.4s cubic-bezier(0,0,0.2,1) forwards',
        'lp-slide-down':'lp-slide-down 0.25s cubic-bezier(0,0,0.2,1) forwards',
      },
    },
  },
  plugins: [tailwindcssAnimate],
};
