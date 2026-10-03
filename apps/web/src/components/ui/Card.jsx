import * as React from 'react';
import { cn } from '../../utils/cn';

const Card = React.forwardRef(
  ({ className, variant, glow, hoverEffect, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'rounded-xl border bg-card text-card-foreground shadow transition-all duration-200',
        variant === 'interactive' && 'hover:border-primary/40 hover:shadow-md cursor-pointer',
        hoverEffect && 'hover:-translate-y-0.5 hover:shadow-lg',
        glow && 'border-primary/50',
        className
      )}
      {...props}
    />
  )
);
Card.displayName = 'Card';

const CardHeader = React.forwardRef(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn('flex flex-col space-y-1.5 p-6', className)}
    {...props}
  />
));
CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef(({ className, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn('font-headline font-semibold leading-none tracking-tight text-foreground flex items-center gap-2', className)}
    {...props}
  />
));
CardTitle.displayName = 'CardTitle';

const CardDescription = React.forwardRef(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn('text-xs text-muted-foreground leading-relaxed', className)}
    {...props}
  />
));
CardDescription.displayName = 'CardDescription';

const CardContent = React.forwardRef(({ className, ...props }, ref) => (
  <div ref={ref} className={cn('p-6 pt-0', className)} {...props} />
));
CardContent.displayName = 'CardContent';

const CardFooter = React.forwardRef(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn('flex items-center p-6 pt-0', className)}
    {...props}
  />
));
CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent };
