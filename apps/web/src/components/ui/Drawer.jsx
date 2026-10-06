import * as React from 'react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from './Sheet';
import { cn } from '../../utils/cn';

const DRAWER_WIDTHS = {
  md: 'w-full sm:max-w-md',
  lg: 'w-full sm:max-w-lg',
  xl: 'w-full sm:max-w-xl',
  '2xl': 'w-full sm:max-w-2xl',
  full: 'w-full',
};

/**
 * Slide-out inspection Drawer built with shadcn/ui Sheet primitives.
 * Preserves CYBERGUARD Drawer API.
 */
export function Drawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  size = 'xl',
  width,
  position = 'right',
  footer,
  className,
}) {
  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose?.()}>
      <SheetContent
        side={position === 'left' ? 'left' : 'right'}
        className={cn(
          'flex flex-col justify-between overflow-y-auto p-0 border-l bg-card text-card-foreground',
          width || DRAWER_WIDTHS[size] || DRAWER_WIDTHS.xl,
          className
        )}
      >
        <div className="flex flex-col flex-1 min-h-0">
          {(title || subtitle) && (
            <SheetHeader className="p-6 border-b shrink-0 bg-muted/30">
              {title && <SheetTitle className="text-xl font-bold">{title}</SheetTitle>}
              {subtitle && <SheetDescription>{subtitle}</SheetDescription>}
            </SheetHeader>
          )}

          <div className="flex-1 p-6 overflow-y-auto space-y-6">{children}</div>
        </div>

        {footer && (
          <SheetFooter className="p-4 border-t bg-muted/30 shrink-0">
            {footer}
          </SheetFooter>
        )}
      </SheetContent>
    </Sheet>
  );
}
