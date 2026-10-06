import * as React from 'react';
import { Toaster as Sonner } from 'sonner';
import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { useTheme } from '../../hooks/useTheme';

const Toaster = ({ ...props }) => {
  const { theme = 'dark' } = useTheme();
  const toasterRef = React.useRef(null);

  // Subtle GSAP entrance for newly mounted toasts: slide-in + fade under 300ms, no bounce/elastic
  useGSAP(
    () => {
      if (typeof window === 'undefined') return;

      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) {
              const toastEl =
                node.matches?.('[data-sonner-toast]')
                  ? node
                  : node.querySelector?.('[data-sonner-toast]');

              if (toastEl && !toastEl.dataset.gsapAnimated) {
                toastEl.dataset.gsapAnimated = 'true';
                gsap.fromTo(
                  toastEl,
                  { opacity: 0, x: 20 },
                  {
                    opacity: 1,
                    x: 0,
                    duration: 0.25,
                    ease: 'power2.out',
                    clearProps: 'transform',
                  }
                );
              }
            }
          });
        }
      });

      // Target document.body where Sonner portals its toaster list
      observer.observe(document.body, { childList: true, subtree: true });

      return () => observer.disconnect();
    },
    { scope: toasterRef }
  );

  return (
    <div ref={toasterRef}>
      <Sonner
        theme={theme}
        className="toaster group"
        toastOptions={{
          classNames: {
            toast:
              'group toast group-[.toaster]:bg-card group-[.toaster]:text-card-foreground group-[.toaster]:border-border group-[.toaster]:shadow-lg font-sans max-w-[calc(100vw-2rem)] sm:max-w-md',
            description: 'group-[.toast]:text-muted-foreground text-xs break-words',
            actionButton:
              'group-[.toast]:bg-primary group-[.toast]:text-primary-foreground text-xs',
            cancelButton:
              'group-[.toast]:bg-muted group-[.toast]:text-muted-foreground text-xs',
          },
        }}
        {...props}
      />
    </div>
  );
};

export { Toaster };
