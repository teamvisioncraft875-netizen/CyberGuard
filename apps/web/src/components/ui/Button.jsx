import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva } from 'class-variance-authority';
import { cn } from '../../utils/cn';
import { Loader2 } from 'lucide-react';

const buttonVariants = cva(
  'inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 select-none cursor-pointer',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground shadow hover:bg-primary/90 active:scale-[0.98]',
        primary:
          'bg-primary text-primary-foreground shadow hover:bg-primary/90 active:scale-[0.98]',
        destructive:
          'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90 active:scale-[0.98]',
        danger:
          'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90 active:scale-[0.98]',
        outline:
          'border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground active:scale-[0.98]',
        secondary:
          'bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80 active:scale-[0.98]',
        ghost:
          'hover:bg-accent hover:text-accent-foreground',
        link:
          'text-primary underline-offset-4 hover:underline',
        warning:
          'bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 active:scale-[0.98]',
        success:
          'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 active:scale-[0.98]',
      },
      size: {
        default: 'h-9 px-4 py-2 text-sm',
        md: 'h-9 px-4 py-2 text-sm',
        sm: 'h-8 rounded-md px-3 text-xs',
        lg: 'h-10 rounded-md px-6 text-base',
        icon: 'h-9 w-9 p-0',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

/**
 * Shadcn/ui Button component with CyberGuard extensions
 */
const Button = React.forwardRef(
  (
    {
      className,
      variant,
      size,
      asChild = false,
      isLoading = false,
      disabled = false,
      icon,
      iconLeft: IconLeft,
      iconRight: IconRight,
      children,
      ...props
    },
    ref
  ) => {
    const Comp = asChild ? Slot : 'button';
    const isDisabled = disabled || isLoading;
    const EffectiveLeft = icon || IconLeft;

    if (asChild) {
      return (
        <Comp
          className={cn(buttonVariants({ variant, size, className }))}
          ref={ref}
          {...props}
        >
          {children}
        </Comp>
      );
    }

    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        disabled={isDisabled}
        {...props}
      >
        {isLoading ? (
          <Loader2 className="mr-2 h-4 w-4 animate-spin text-current" />
        ) : EffectiveLeft ? (
          <span className={cn('inline-flex shrink-0', children ? 'mr-2' : '')}>
            {React.isValidElement(EffectiveLeft) ? (
              EffectiveLeft
            ) : (
              <EffectiveLeft className="h-4 w-4" />
            )}
          </span>
        ) : null}

        {children}

        {!isLoading && IconRight ? (
          <span className={cn('inline-flex shrink-0', children ? 'ml-2' : '')}>
            {React.isValidElement(IconRight) ? (
              IconRight
            ) : (
              <IconRight className="h-4 w-4" />
            )}
          </span>
        ) : null}
      </Comp>
    );
  }
);

Button.displayName = 'Button';

export { Button, buttonVariants };
