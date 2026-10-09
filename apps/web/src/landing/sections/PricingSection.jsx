import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const TIERS = [
  {
    name: 'Free',
    tagline: 'Essential security for individuals and everyday browsing.',
    priceMonthly: 0,
    priceAnnual: 0,
    badge: 'Always Free',
    highlight: false,
    cta: 'Get Free Protection',
    ctaHref: '#download',
    features: [
      'URL & Phishing real-time detection',
      'On-device local threat scanning',
      'Up to 2 active devices',
      'Standard community support',
      'Daily threat definitions update',
      'Zero personal data retention',
    ],
  },
  {
    name: 'Pro',
    tagline: 'Full spectrum protection with all 6 engines and unlimited devices.',
    priceMonthly: 19,
    priceAnnual: 15,
    badge: 'Most Popular',
    highlight: true,
    cta: 'Upgrade to Pro',
    ctaHref: '/signup',
    features: [
      'All 6 Production Detection Engines',
      'Deepfake image & audio verification',
      'Unlimited devices & secure cloud sync',
      'Secret & API key exposure scanner',
      'Priority threat push notifications',
      'Priority 24/7 technical support',
    ],
  },
  {
    name: 'Enterprise',
    tagline: 'SOC orchestration, autonomous SOAR playbooks, and AI Copilot.',
    priceMonthly: 'Custom',
    priceAnnual: 'Custom',
    badge: 'Tailored SLA',
    highlight: false,
    cta: 'Contact Enterprise',
    ctaHref: 'mailto:sales@cyberguard.com',
    features: [
      'Everything in Pro plus SOC Command',
      'AI Threat Copilot natural-language triage',
      'Automated SOAR playbook execution',
      'SIEM & Webhook telemetry export',
      'Dedicated Slack channel & 99.99% SLA',
      'Custom on-premise model deployments',
    ],
  },
];

export default function PricingSection() {
  const [annual, setAnnual] = useState(true);
  const navigate = useNavigate();

  const handleCta = (href) => {
    if (href.startsWith('#')) {
      const el = document.querySelector(href);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (href.startsWith('mailto:')) {
      window.location.href = href;
    } else {
      navigate(href);
    }
  };

  return (
    <section
      id="pricing"
      className="relative bg-[#0F0F0F] py-24 px-6 md:px-10 lg:px-16 overflow-hidden border-t border-[#1F1F1F]"
    >
      {/* Background ambient glow */}
      <div
        className="pointer-events-none absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-[#00D9FF]/4 rounded-full blur-[140px]"
        aria-hidden="true"
      />

      <div className="max-w-[1280px] mx-auto relative z-10">
        {/* Section Heading */}
        <div className="text-center max-w-2xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#1A1A1A] border border-[#2D2D2D] text-[#00D9FF] text-xs font-semibold uppercase tracking-wider mb-4">
            <span className="w-2 h-2 rounded-full bg-[#00D9FF]" />
            Transparent Pricing
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight mb-4">
            Simple, predictable tiers.
          </h2>
          <p className="text-base sm:text-lg text-[#9CA3AF] leading-relaxed mb-8">
            Start free on any device. Upgrade when you need deepfake analysis, secret scanning, or enterprise SOC orchestration.
          </p>

          {/* Billing Switch */}
          <div className="inline-flex items-center bg-[#171717] p-1 rounded-full border border-[#2A2A2A]">
            <button
              type="button"
              onClick={() => setAnnual(false)}
              className={`px-4 py-2 rounded-full text-xs sm:text-sm font-medium transition-all duration-200 ${
                !annual ? 'bg-[#262626] text-white shadow-sm' : 'text-[#888888] hover:text-white'
              }`}
            >
              Monthly Billing
            </button>
            <button
              type="button"
              onClick={() => setAnnual(true)}
              className={`px-4 py-2 rounded-full text-xs sm:text-sm font-medium transition-all duration-200 flex items-center gap-2 ${
                annual ? 'bg-[#262626] text-white shadow-sm' : 'text-[#888888] hover:text-white'
              }`}
            >
              Annual Billing
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-[#00D9FF]/15 text-[#00D9FF] border border-[#00D9FF]/30">
                Save 20%
              </span>
            </button>
          </div>
        </div>

        {/* Pricing Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 items-stretch">
          {TIERS.map((tier) => (
            <div
              key={tier.name}
              className={`rounded-2xl flex flex-col justify-between p-8 transition-all duration-300 relative ${
                tier.highlight
                  ? 'bg-[#181818] border-2 border-[#00D9FF] shadow-[0_8px_32px_rgba(0,217,255,0.12)] md:-translate-y-2'
                  : 'bg-[#141414] border border-[#262626] hover:border-[#383838]'
              }`}
            >
              {/* Badge */}
              <div className="flex items-center justify-between mb-4">
                <span className="font-mono text-sm uppercase tracking-wider text-[#9CA3AF]">
                  {tier.name}
                </span>
                <span
                  className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${
                    tier.highlight
                      ? 'bg-[#00D9FF]/15 text-[#00D9FF] border-[#00D9FF]/30'
                      : 'bg-[#222222] text-[#888888] border-[#303030]'
                  }`}
                >
                  {tier.badge}
                </span>
              </div>

              {/* Tagline */}
              <p className="text-xs text-[#888888] min-h-[36px] mb-6">
                {tier.tagline}
              </p>

              {/* Price display */}
              <div className="mb-8">
                {typeof tier.priceMonthly === 'number' ? (
                  <div className="flex items-baseline gap-1">
                    <span className="text-4xl sm:text-5xl font-black text-white tracking-tight">
                      ${annual ? tier.priceAnnual : tier.priceMonthly}
                    </span>
                    <span className="text-sm text-[#888888]">
                      / month {annual && <span className="text-xs text-[#00D9FF] block">billed annually</span>}
                    </span>
                  </div>
                ) : (
                  <div className="text-4xl sm:text-5xl font-black text-white tracking-tight">
                    Custom
                  </div>
                )}
              </div>

              {/* Features list */}
              <div className="space-y-3.5 mb-8 flex-1">
                {tier.features.map((feat, idx) => (
                  <div key={idx} className="flex items-start gap-3">
                    <div className="w-5 h-5 rounded-full bg-[#00D9FF]/10 text-[#00D9FF] flex items-center justify-center shrink-0 mt-0.5">
                      <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    </div>
                    <span className="text-sm text-[#CCCCCC] leading-snug">{feat}</span>
                  </div>
                ))}
              </div>

              {/* Action Button */}
              <button
                type="button"
                onClick={() => handleCta(tier.ctaHref)}
                className={`w-full py-3.5 px-6 rounded-xl text-sm font-bold transition-all duration-200 cursor-pointer ${
                  tier.highlight
                    ? 'bg-[#00D9FF] text-[#0F0F0F] hover:bg-[#00C2E5] shadow-[0_0_20px_rgba(0,217,255,0.3)]'
                    : 'bg-[#222222] text-white hover:bg-[#2A2A2A] border border-[#333333]'
                }`}
              >
                {tier.cta}
              </button>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
