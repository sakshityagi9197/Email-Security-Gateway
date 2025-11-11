import { useEffect, useRef, useCallback } from 'react';
import { useLocation } from 'react-router-dom';

import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import { useWebSocket } from '../hooks/useWebSocket.js';

export default function NotificationWatcher() {
  const { isAuthenticated, apiFetch, lastSeenCreatedAt, updateLastSeen, apiBase } = useAuth();
  const { push } = useToast();
  const location = useLocation();
  const cancelledRef = useRef(false);

  // Try WebSocket first, fall back to polling if not available
  const wsUrl = apiBase
    ? apiBase.replace(/^http/, 'ws') + '/ws/notifications'
    : null;

  const handleWebSocketMessage = useCallback((event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'new_email' && !cancelledRef.current) {
        const subject = data.subject ? ` - ${data.subject}` : '';
        push(`New email received${subject}`, { variant: 'info' });
        if (data.created_at) {
          updateLastSeen(data.created_at);
        }
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('emails:refresh'));
        }
      }
    } catch (err) {
      console.warn('Failed to parse WebSocket message', err);
    }
  }, [push, updateLastSeen]);

  const { connected } = useWebSocket(wsUrl, {
    onMessage: handleWebSocketMessage,
    enabled: isAuthenticated && Boolean(wsUrl),
    reconnectInterval: 5000,
    maxReconnectAttempts: 3,
  });

  // Fallback to polling if WebSocket not connected
  useEffect(() => {
    if (!isAuthenticated || connected) return undefined;

    cancelledRef.current = false;

    const fetchLatest = async () => {
      try {
        const res = await apiFetch('/analysis');
        if (!res.ok) return;
        const items = await res.json();
        const latest = Array.isArray(items) ? items[0] : null;
        if (!latest?.created_at) return;
        if (!lastSeenCreatedAt) {
          updateLastSeen(latest.created_at);
          return;
        }
        if (String(latest.created_at) > String(lastSeenCreatedAt)) {
          updateLastSeen(latest.created_at);
          if (!cancelledRef.current) {
            const subject = latest.subject ? ` - ${latest.subject}` : '';
            push(`New email received${subject}`, { variant: 'info' });
            if (typeof window !== 'undefined') {
              window.dispatchEvent(new CustomEvent('emails:refresh'));
            }
          }
        }
      } catch (err) {
        console.warn('Notification poll failed', err);
      }
    };

    // Poll every 30 seconds (increased from 10s) as fallback
    fetchLatest();
    const timer = setInterval(fetchLatest, 30000);

    return () => {
      cancelledRef.current = true;
      clearInterval(timer);
    };
  }, [apiFetch, isAuthenticated, lastSeenCreatedAt, push, updateLastSeen, connected, location.key]);

  return null;
}