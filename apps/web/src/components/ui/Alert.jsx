import * as React from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../../utils/cn';
import {
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Info,
  ShieldAlert,
  X,
} from 'lucide-react';

const alertVariants = cva(
  'relative w-full rounded-xl border p-4 [&>svg~*]:pl-7 [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground transition-all',
  {
    variants: {
      variant: {
        default: 'bg-background text-foreground border-border',
        info: 'bg-sky-50 dark:bg-sky-950/30 text-sky-900 dark:text-sky-300 border-sky-300 dark:border-sky-800/40 [&>svg]:text-sky-600 dark:[&>svg]:text-sky-400',
        success:
          'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800/40 [&>svg]:text-emerald-600 dark:[&>svg]:text-emerald-400',
        warning:
          'bg-amber-50 dark:bg-amber-950/30 text-amber-900 dark:text-amber-300 border-amber-300 dark:border-amber-800/40 [&>svg]:text-amber-600 dark:[&>svg]:text-amber-400',
        destructive:
          'bg-rose-50 dark:bg-rose-950/30 text-rose-900 dark:text-rose-300 border-rose-300 dark:border-rose-800/40 [&>svg]:text-rose-600 dark:[&>svg]:text-rose-400',
        critical:
          'bg-rose-50 dark:bg-rose-950/40 text-rose-900 dark:text-rose-300 border-rose-300 dark:border-rose-800/50 [&>svg]:text-rose-600 dark:[&>svg]:text-rose-400',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

const ALERT_ICONS = {
  default: Info,
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  destructive: AlertCircle,
  critical: ShieldAlert,
};

const Alert = React.forwardRef(
  ({ className, variant = 'default', type, title, children, onClose, ...props }, ref) => {
    const effectiveVariant = type || variant || 'default';
    const Icon = ALERT_ICONS[effectiveVariant] || Info;

    return (
      <div
        ref={ref}
        role="alert"
        className={cn(alertVariants({ variant: effectiveVariant }), className)}
        {...props}
      >
        <Icon className="h-4 w-4" />
        <div className="flex-1">
          {title && <AlertTitle>{title}</AlertTitle>}
          <AlertDescription>{children}</AlertDescription>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="absolute top-3.5 right-3.5 p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    );
  }
);
Alert.displayName = 'Alert';

const AlertTitle = React.forwardRef(({ className, ...props }, ref) => (
  <h5
    ref={ref}
    className={cn('mb-1 font-headline font-semibold leading-none tracking-tight text-foreground', className)}
    {...props}
  />
));
AlertTitle.displayName = 'AlertTitle';

const AlertDescription = React.forwardRef(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn('text-xs leading-relaxed text-muted-foreground [&_p]:leading-relaxed', className)}
    {...props}
  />
));
AlertDescription.displayName = 'AlertDescription';

export { Alert, AlertTitle, AlertDescription, alertVariants };
