import * as React from 'react';
import { cn } from '../../utils/cn';
import { ChevronDown } from 'lucide-react';

/**
 * Shadcn/ui Select component with CyberGuard label, error, helperText, and custom chevron.
 */
const Select = React.forwardRef(
  (
    {
      className,
      label,
      error,
      helperText,
      containerClassName,
      disabled = false,
      children,
      id,
      ...props
    },
    ref
  ) => {
    const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);

    return (
      <div className={cn('flex flex-col gap-1.5', containerClassName)}>
        {label ? (
          <label
            htmlFor={selectId}
            className="text-xs font-semibold tracking-wide text-foreground/80 uppercase"
          >
            {label}
          </label>
        ) : null}

        <div className="relative flex items-center w-full">
          <select
            id={selectId}
            ref={ref}
            disabled={disabled}
            className={cn(
              'flex h-9 w-full appearance-none rounded-lg border border-input bg-background px-3 py-1.5 pr-8 text-xs text-foreground shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 font-sans cursor-pointer',
              error && 'border-destructive focus-visible:ring-destructive text-destructive',
              className
            )}
            {...props}
          >
            {children}
          </select>
          <ChevronDown className="pointer-events-none absolute right-2.5 h-3.5 w-3.5 text-muted-foreground" />
        </div>

        {error ? (
          <span className="text-[11px] text-destructive">{error}</span>
        ) : helperText ? (
          <span className="text-[11px] text-muted-foreground">{helperText}</span>
        ) : null}
      </div>
    );
  }
);

Select.displayName = 'Select';

export { Select };
