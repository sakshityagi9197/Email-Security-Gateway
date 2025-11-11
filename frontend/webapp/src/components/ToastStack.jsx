import { useToast } from '../context/ToastContext.jsx';

const VARIANT_CLASSES = {
  default: 'bg-dark text-white',
  success: 'bg-success text-white',
  danger: 'bg-danger text-white',
  warning: 'bg-warning text-dark',
  info: 'bg-info text-dark',
};

export default function ToastStack() {
  const { toasts, dismiss } = useToast();

  if (!toasts.length) return null;

  return (
    <div className="toast-stack position-fixed top-0 end-0 p-3" style={{ zIndex: 1080, width: 'min(400px, 100%)' }}>
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`toast-item shadow rounded-3 p-3 mb-2 ${VARIANT_CLASSES[toast.variant] || VARIANT_CLASSES.default}`}
          role="status"
          onClick={() => dismiss(toast.id)}
          style={{ cursor: 'pointer' }}
        >
          {toast.message}
        </div>
      ))}
    </div>
  );
}