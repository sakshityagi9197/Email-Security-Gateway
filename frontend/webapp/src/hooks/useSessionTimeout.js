import { useEffect, useCallback, useRef } from 'react';

/**
 * Hook to handle session timeout after inactivity
 * @param {Function} onTimeout - Callback when session times out
 * @param {number} timeoutMs - Timeout in milliseconds (default: 15 minutes)
 * @param {boolean} enabled - Whether timeout is enabled
 */
export function useSessionTimeout(onTimeout, timeoutMs = 15 * 60 * 1000, enabled = true) {
  const timeoutRef = useRef(null);

  const resetTimeout = useCallback(() => {
    if (!enabled) return;

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    timeoutRef.current = setTimeout(() => {
      if (onTimeout) {
        onTimeout();
      }
    }, timeoutMs);
  }, [enabled, onTimeout, timeoutMs]);

  useEffect(() => {
    if (!enabled) return;

    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];

    const handleActivity = () => {
      resetTimeout();
    };

    // Set initial timeout
    resetTimeout();

    // Add event listeners
    events.forEach((event) => {
      window.addEventListener(event, handleActivity, true);
    });

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      events.forEach((event) => {
        window.removeEventListener(event, handleActivity, true);
      });
    };
  }, [enabled, resetTimeout]);

  return resetTimeout;
}
