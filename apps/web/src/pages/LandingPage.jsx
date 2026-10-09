import React, { useEffect } from 'react';
import '../landing/landing.css';
import LandingNav from '../landing/components/LandingNav';
import HeroSection from '../landing/sections/HeroSection';
import ValuePropSection from '../landing/sections/ValuePropSection';
import HowItWorksSection from '../landing/sections/HowItWorksSection';
import EnginesSection from '../landing/sections/EnginesSection';
import PricingSection from '../landing/sections/PricingSection';
import DownloadSection from '../landing/sections/DownloadSection';
import FAQSection from '../landing/sections/FAQSection';
import FooterSection from '../landing/sections/FooterSection';
import ScrollToTop from '../landing/components/ScrollToTop';

/**
 * LandingPage — Full-featured marketing landing page for CYBERGUARD.
 * Route: /landing
 * Standalone dark-mode design system matching fora.so reference.
 */
export default function LandingPage() {
  useEffect(() => {
    // Set page title for SEO & best practices
    document.title = 'CYBERGUARD — AI-Powered Cyber Defense Platform';
  }, []);

  return (
    <div
      className="landing-root landing-page-enter"
      style={{
        background: '#0F0F0F',
        minHeight: '100vh',
        width: '100%',
        overflowX: 'hidden',
        color: '#E5E5E5',
        position: 'relative',
      }}
    >
      {/* Sticky Top Navigation */}
      <LandingNav />

      {/* Main Content Flow */}
      <main>
        {/* 1. Hero with landscape background and CTA */}
        <HeroSection />

        {/* 2. Value Proposition (Personal vs Enterprise split) */}
        <ValuePropSection />

        {/* 3. How It Works (4-step security workflow) */}
        <HowItWorksSection />

        {/* 4. 6 Detection Engines Showcase Grid */}
        <EnginesSection />

        {/* 5. Transparent Pricing Tiers (Free | Pro | Enterprise) */}
        <PricingSection />

        {/* 6. Multi-Platform Download Center (iOS | Android | Web | Windows | Linux) */}
        <DownloadSection />

        {/* 7. Frequently Asked Questions Accordion */}
        <FAQSection />
      </main>

      {/* 8. Multi-Column Footer */}
      <FooterSection />

      {/* Floating Scroll-to-Top Button */}
      <ScrollToTop />
    </div>
  );
}
