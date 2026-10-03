import * as React from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from './Dialog';
import { cn } from '../../utils/cn';

const MODAL_SIZES = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-[95vw] max-h-[92vh]',
};

/**
 * Modal wrapper built with shadcn/ui Dialog primitives.
 * Preserves existing CYBERGUARD Modal API.
 */
export function Modal({
  isOpen,
  onClose,
  title,
  description,
  children,
  size = 'md',
  showCloseButton = true,
  className,
  overlayClassName,
}) {
  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose?.()}>
      <DialogContent
        className={cn(
          MODAL_SIZES[size] || MODAL_SIZES.md,
          'border bg-card text-card-foreground',
          className
        )}
      >
        {(title || description) && (
          <DialogHeader className="border-b pb-4">
            {title && <DialogTitle className="text-xl font-bold">{title}</DialogTitle>}
            {description && <DialogDescription>{description}</DialogDescription>}
          </DialogHeader>
        )}
        <div className="py-2">{children}</div>
      </DialogContent>
    </Dialog>
  );
}
