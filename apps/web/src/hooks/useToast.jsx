import * as React from 'react';
import { toast as sonnerToast } from 'sonner';
import { Toaster } from '../components/ui/Sonner';

const ToastContext = React.createContext(null);

export const toast = {
  success: (message, options) => {
    return sonnerToast.success(typeof message === 'object' ? message.message || message.title : message, {
      description: typeof message === 'object' ? message.description || message.message : options?.description,
      ...options,
    });
  },
  error: (message, options) => {
    return sonnerToast.error(typeof message === 'object' ? message.message || message.title : message, {
      description: typeof message === 'object' ? message.description || message.message : options?.description,
      ...options,
    });
  },
  warning: (message, options) => {
    return sonnerToast.warning(typeof message === 'object' ? message.message || message.title : message, {
      description: typeof message === 'object' ? message.description || message.message : options?.description,
      ...options,
    });
  },
  info: (message, options) => {
    return sonnerToast.info(typeof message === 'object' ? message.message || message.title : message, {
      description: typeof message === 'object' ? message.description || message.message : options?.description,
      ...options,
    });
  },
  critical: (message, options) => {
    return sonnerToast.error(typeof message === 'object' ? message.message || message.title : message, {
      description: typeof message === 'object' ? message.description || message.message : options?.description,
      className: 'border-destructive text-destructive bg-destructive/10',
      ...options,
    });
  },
  show: ({ type = 'info', title, message, ...options }) => {
    const handler = toast[type] || toast.info;
    return handler(title || message, { description: title ? message : undefined, ...options });
  },
  dismiss: (id) => sonnerToast.dismiss(id),
};

export function ToastProvider({ children }) {
  const addToast = React.useCallback(({ type = 'info', title, message, ...options }) => {
    return toast.show({ type, title, message, ...options });
  }, []);

  const contextValue = React.useMemo(
    () => ({
      ...toast,
      addToast,
      showToast: toast.show,
    }),
    [addToast]
  );

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <Toaster position="bottom-right" richColors closeButton />
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = React.useContext(ToastContext);
  if (!context) {
    // If used outside provider, return standalone toast helper directly
    return {
      ...toast,
      addToast: ({ type = 'info', title, message }) => toast.show({ type, title, message }),
      showToast: toast.show,
    };
  }
  return context;
}
