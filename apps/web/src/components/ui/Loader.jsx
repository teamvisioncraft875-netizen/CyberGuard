import * as React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';
import { Skeleton } from './Skeleton';

const LOADER_SIZES = {
  sm: 'w-4 h-4',
  md: 'w-6 h-6',
  lg: 'w-10 h-10',
  xl: 'w-14 h-14',
};

/**
 * CyberGuard multi-purpose Loader component
 * Supports inline spinner, full-page backdrop, or skeleton variant.
 */
export function Loader({
  size = 'md',
  variant = 'spinner',
  text,
  fullPage = false,
  className,
  ...props
}) {
  if (variant === 'skeleton') {
    return <Skeleton className={cn('w-full h-8', className)} {...props} />;
  }

  const content = (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 text-muted-foreground select-none',
        className
      )}
      {...props}
    >
      <Loader2
        className={cn(
          'animate-spin text-primary',
          LOADER_SIZES[size] || LOADER_SIZES.md
        )}
      />
      {text && (
        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground font-medium">
          {text}
        </span>
      )}
    </div>
  );

  if (fullPage) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-md">
        {content}
      </div>
    );
  }

  return content;
}

export { Skeleton };
