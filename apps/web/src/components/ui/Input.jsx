import * as React from 'react';
import { cn } from '../../utils/cn';
import { Eye, EyeOff, AlertCircle, X } from 'lucide-react';

/**
 * Shadcn/ui Input component with CyberGuard label, error, helperText, and password support
 */
const Input = React.forwardRef(
  (
    {
      className,
      type = 'text',
      label,
      error,
      helperText,
      iconLeft: IconLeft,
      iconRight: IconRight,
      containerClassName,
      onClear,
      disabled = false,
      value,
      id,
      ...props
    },
    ref
  ) => {
    const [showPassword, setShowPassword] = React.useState(false);
    const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);
    const isPassword = type === 'password';
    const effectiveType = isPassword ? (showPassword ? 'text' : 'password') : type;

    return (
      <div className={cn('w-full flex flex-col gap-1.5', containerClassName)}>
        {label ? (
          <label
            htmlFor={inputId}
            className="text-xs font-semibold tracking-wide text-foreground/80 uppercase flex items-center justify-between"
          >
            <span>{label}</span>
          </label>
        ) : null}

        <div className="relative flex items-center w-full">
          {IconLeft ? (
            <div className="absolute left-3 flex items-center pointer-events-none text-muted-foreground">
              {React.isValidElement(IconLeft) ? IconLeft : <IconLeft className="h-4 w-4" />}
            </div>
          ) : null}

          <input
            type={effectiveType}
            id={inputId}
            ref={ref}
            value={value}
            disabled={disabled}
            className={cn(
              'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 text-foreground',
              IconLeft && 'pl-9',
              (IconRight || isPassword || onClear) && 'pr-9',
              error && 'border-destructive focus-visible:ring-destructive text-destructive',
              className
            )}
            {...props}
          />

          {/* Clear Button */}
          {onClear && value ? (
            <button
              type="button"
              onClick={onClear}
              className="absolute right-2.5 p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          ) : isPassword ? (
            <button
              type="button"
              onClick={() => setShowPassword((prev) => !prev)}
              className="absolute right-2.5 p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              tabIndex={-1}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          ) : IconRight ? (
            <div className="absolute right-3 flex items-center pointer-events-none text-muted-foreground">
              {React.isValidElement(IconRight) ? IconRight : <IconRight className="h-4 w-4" />}
            </div>
          ) : null}
        </div>

        {error ? (
          <p className="text-xs text-destructive flex items-center gap-1.5 mt-0.5 animate-in fade-in">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span>{error}</span>
          </p>
        ) : helperText ? (
          <p className="text-xs text-muted-foreground mt-0.5">{helperText}</p>
        ) : null}
      </div>
    );
  }
);

Input.displayName = 'Input';

export { Input };
