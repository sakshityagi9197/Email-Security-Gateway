import { useEffect, useRef, useCallback, useState } from 'react';

/**
 * Hook to manage WebSocket connections with automatic reconnection
 * @param {string} url - WebSocket URL
 * @param {Object} options - Options
 * @returns {Object} { connected, send, close }
 */
export function useWebSocket(url, options = {}) {
  const {
    onMessage,
    onOpen,
    onClose,
    onError,
    reconnectInterval = 5000,
    maxReconnectAttempts = 5,
    enabled = true,
  } = options;

  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef(null);
  const shouldReconnectRef = useRef(true);

  const connect = useCallback(() => {
    if (!enabled || !url) return;

    try {
      const ws = new WebSocket(url);

      ws.onopen = (event) => {
        setConnected(true);
        reconnectAttemptsRef.current = 0;
        if (onOpen) onOpen(event);
      };

      ws.onmessage = (event) => {
        if (onMessage) onMessage(event);
      };

      ws.onerror = (event) => {
        console.error('WebSocket error:', event);
        if (onError) onError(event);
      };

      ws.onclose = (event) => {
        setConnected(false);
        wsRef.current = null;
        if (onClose) onClose(event);

        // Attempt to reconnect
        if (shouldReconnectRef.current && reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      wsRef.current = ws;
    } catch (error) {
      console.error('WebSocket connection error:', error);
    }
  }, [enabled, url, onMessage, onOpen, onClose, onError, reconnectInterval, maxReconnectAttempts]);

  const send = useCallback((data) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data));
      return true;
    }
    return false;
  }, []);

  const close = useCallback(() => {
    shouldReconnectRef.current = false;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
  }, []);

  useEffect(() => {
    if (enabled && url) {
      connect();
    }

    return () => {
      shouldReconnectRef.current = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [enabled, url, connect]);

  return { connected, send, close };
}
