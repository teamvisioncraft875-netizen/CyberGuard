import * as React from 'react';
import { Card, CardContent } from './Card';
import { Button } from './Button';
import { ShieldCheck } from 'lucide-react';
import { cn } from '../../utils/cn';

/**
 * EmptyState component built from shadcn/ui primitives (Card, Button).
 * Displays a clean placeholder when feeds or search queries are empty.
 */
export function EmptyState({
  icon: Icon = ShieldCheck,
  title = 'No Data Found',
  description = 'There are no active records matching your filter criteria.',
  actionLabel,
  onAction,
  action,
  className,
  children,
}) {
  return (
    <Card className={cn('border-dashed bg-muted/20 text-center', className)}>
      <CardContent className="flex flex-col items-center justify-center py-12 px-6 text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
          {React.isValidElement(Icon) ? Icon : <Icon className="w-6 h-6" />}
        </div>

        <div className="space-y-1 max-w-sm">
          <h3 className="font-headline font-semibold text-base text-foreground">
            {title}
          </h3>
          <p className="text-xs text-muted-foreground leading-relaxed">
            {description}
          </p>
        </div>

        {action ? (
          action
        ) : actionLabel && onAction ? (
          <Button variant="outline" size="sm" onClick={onAction}>
            {actionLabel}
          </Button>
        ) : null}

        {children}
      </CardContent>
    </Card>
  );
}
