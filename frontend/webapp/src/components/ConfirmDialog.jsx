import { useEffect, useRef } from 'react';

/**
 * Custom confirmation dialog component
 */
export default function ConfirmDialog({ isOpen, onClose, onConfirm, title, message, confirmText = 'Confirm', confirmVariant = 'danger', requireTyping = false, typeText = 'DELETE' }) {
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen && requireTyping && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen, requireTyping]);

  useEffect(() => {
    if (!isOpen) return;

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (requireTyping) {
      const input = inputRef.current?.value || '';
      if (input === typeText) {
        onConfirm();
      }
    } else {
      onConfirm();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal show d-block" tabIndex="-1" role="dialog" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">{title || 'Confirm Action'}</h5>
            <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
          </div>
          <form onSubmit={handleSubmit}>
            <div className="modal-body">
              <p>{message || 'Are you sure you want to proceed?'}</p>
              {requireTyping && (
                <div className="mt-3">
                  <label className="form-label">
                    Type <strong>{typeText}</strong> to confirm:
                  </label>
                  <input
                    ref={inputRef}
                    type="text"
                    className="form-control"
                    placeholder={typeText}
                    required
                    pattern={typeText}
                    title={`Must type ${typeText} exactly`}
                  />
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className={`btn btn-${confirmVariant}`}>
                {confirmText}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
