import React, { useState, useRef, useEffect } from 'react';

export const FAQ_ITEMS = [
  {
    q: 'Is CYBERGUARD really free?',
    a: 'Yes, CYBERGUARD is free to download and use. We offer both free and premium features.',
  },
  {
    q: 'How does it protect me?',
    a: 'CYBERGUARD uses 6 detection engines to scan URLs, messages, media, and more in real-time.',
  },
  {
    q: 'Will it slow down my phone?',
    a: 'No. CYBERGUARD runs efficiently in the background with minimal battery impact.',
  },
  {
    q: 'Can I use it on multiple devices?',
    a: 'Yes. Download on all your devices and your data syncs securely.',
  },
  {
    q: 'Is my data private?',
    a: 'Absolutely. We do not store personal data. All scanning happens on your device.',
  },
  {
    q: 'What about for enterprises?',
    a: 'We offer CYBERGUARD Enterprise with AI Copilot, SOAR automation, and more.',
  },
  {
    q: 'How do I get support?',
    a: 'Contact us at support@cyberguard.com or visit our docs at docs.cyberguard.com',
  },
  {
    q: 'Is there a desktop version?',
    a: 'Yes. Windows, Linux, and web versions available.',
  },
];

function FAQCard({ item, index, isOpen, onToggle }) {
  const contentRef = useRef(null);
  const [maxHeight, setMaxHeight] = useState(0);

  useEffect(() => {
    if (contentRef.current) {
      setMaxHeight(isOpen ? contentRef.current.scrollHeight : 0);
    }
  }, [isOpen]);

  return (
    <div
      className={`group rounded-xl border transition-all duration-300 ease-in-out overflow-hidden ${
        isOpen
          ? 'bg-[#1A1A1A] border-[#00D9FF]/40 shadow-[0_4px_24px_rgba(0,217,255,0.06)]'
          : 'bg-[#141414] border-[#2D2D2D] hover:border-[#3D3D3D] hover:bg-[#181818]'
      }`}
    >
      <button
        type="button"
        onClick={() => onToggle(index)}
        aria-expanded={isOpen}
        aria-controls={`faq-answer-${index}`}
        id={`faq-question-${index}`}
        className="w-full text-left px-6 py-5 flex items-center justify-between gap-4 cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00D9FF]"
      >
        <span
          className={`font-sans font-bold text-white transition-colors duration-200 ${
            isOpen ? 'text-[#00D9FF]' : 'text-white group-hover:text-[#F3F4F6]'
          }`}
          style={{ fontSize: '16pt', lineHeight: 1.35 }}
        >
          {item.q}
        </span>

        {/* Chevron Icon */}
        <div
          className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center transition-all duration-300 ${
            isOpen
              ? 'bg-[#00D9FF]/15 text-[#00D9FF] rotate-180 border border-[#00D9FF]/30'
              : 'bg-[#222222] text-[#9CA3AF] group-hover:text-white border border-[#2E2E2E]'
          }`}
        >
          <svg
            className="w-4 h-4 transition-transform duration-300"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </div>
      </button>

      {/* Answer Panel with smooth expand/collapse */}
      <div
        id={`faq-answer-${index}`}
        role="region"
        aria-labelledby={`faq-question-${index}`}
        style={{
          maxHeight: `${maxHeight}px`,
          transition: 'max-height 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
        className="overflow-hidden"
      >
        <div ref={contentRef} className="px-6 pb-6 pt-1">
          <div className="h-[1px] w-full bg-[#2A2A2A] mb-4 opacity-60" />
          <p
            className="font-sans text-[#E5E5E5] leading-relaxed"
            style={{ fontSize: '14pt' }}
          >
            {item.a}
          </p>
        </div>
      </div>
    </div>
  );
}

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState(0); // First open by default, single accordion open

  const handleToggle = (index) => {
    setOpenIndex((prev) => (prev === index ? null : index));
  };

  return (
    <section
      id="faq"
      className="relative bg-[#0F0F0F] py-20 px-6 md:px-10 lg:px-16 overflow-hidden"
    >
      {/* Background glow decorations */}
      <div
        className="pointer-events-none absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-[#00D9FF]/5 rounded-full blur-[120px]"
        aria-hidden="true"
      />

      <div className="max-w-[960px] mx-auto relative z-10">
        {/* Header */}
        <div className="text-center mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#1A1A1A] border border-[#2D2D2D] text-[#00D9FF] text-xs font-semibold uppercase tracking-wider mb-4">
            <span className="w-2 h-2 rounded-full bg-[#00D9FF] animate-pulse" />
            Got Questions?
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-white tracking-tight mb-4">
            Frequently Asked Questions
          </h2>
          <p className="text-base sm:text-lg text-[#9CA3AF] max-w-xl mx-auto">
            Everything you need to know about CYBERGUARD security engines, privacy commitments, and device availability.
          </p>
        </div>

        {/* Accordion List */}
        <div className="space-y-4">
          {FAQ_ITEMS.map((item, idx) => (
            <FAQCard
              key={idx}
              item={item}
              index={idx}
              isOpen={openIndex === idx}
              onToggle={handleToggle}
            />
          ))}
        </div>

        {/* Additional Help Callout */}
        <div className="mt-12 text-center p-6 rounded-2xl bg-[#141414] border border-[#2D2D2D] flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-left">
            <h4 className="text-white font-semibold text-base mb-1">Still have questions?</h4>
            <p className="text-sm text-[#9CA3AF]">
              Our security specialists and engineering support team are here 24/7.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <a
              href="mailto:support@cyberguard.com"
              className="inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-[#222222] hover:bg-[#2A2A2A] text-white text-sm font-medium border border-[#333333] transition-colors duration-200"
            >
              Email Support
            </a>
            <a
              href="https://docs.cyberguard.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center px-4 py-2.5 rounded-lg bg-[#00D9FF] hover:bg-[#00C2E5] text-[#0F0F0F] text-sm font-semibold transition-all duration-200 shadow-[0_0_15px_rgba(0,217,255,0.3)]"
            >
              Visit Docs
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
