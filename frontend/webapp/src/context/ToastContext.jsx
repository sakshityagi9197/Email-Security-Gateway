import { createContext, useCallback, useContext, useMemo, useState } from 'react';

const ToastContext = createContext(null);
let toastIdCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback((message, opts = {}) => {
    const id = ++toastIdCounter;
    const toast = {
      id,
      message,
      variant: opts.variant || 'default',
      // By default make toasts persistent unless a duration > 0 is provided
      duration: opts.duration ?? 0,
      persistent: typeof opts.persistent === 'boolean' ? opts.persistent : (opts.duration === undefined ? true : opts.duration === 0),
    };

    setToasts((prev) => [toast, ...prev]);

    // Auto-dismiss if not persistent and duration > 0
    if (!toast.persistent && toast.duration > 0) {
      setTimeout(() => dismiss(id), toast.duration);
    }

    return id;
  }, [dismiss]);

  const value = useMemo(() => ({ push, dismiss, toasts }), [push, dismiss, toasts]);

  return (
    <ToastContext.Provider value={value}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}