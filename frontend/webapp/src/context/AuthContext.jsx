import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { getCsrfToken } from '../utils/helpers.js';
import { useSessionTimeout } from '../hooks/useSessionTimeout.js';

const AuthContext = createContext(null);

// Use sessionStorage instead of localStorage for better security
function parseStoredJson(key, fallback = null) {
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`Failed to parse sessionStorage key "${key}"`, err);
    return fallback;
  }
}

// API base URL from environment variable only - cannot be manipulated
const DEFAULT_API_BASE = (() => {
  if (import.meta.env?.VITE_API_BASE) return import.meta.env.VITE_API_BASE;
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return 'http://127.0.0.1:8000';
})();

export function AuthProvider({ children }) {
  const apiBase = DEFAULT_API_BASE; // Fixed API base - cannot be changed
  const [accessToken, setAccessToken] = useState(() => sessionStorage.getItem('accessToken'));
  const [refreshToken, setRefreshToken] = useState(() => sessionStorage.getItem('refreshToken'));
  const [user, setUser] = useState(() => parseStoredJson('user'));
  const [roles, setRoles] = useState(() => parseStoredJson('roles', []));
  const [lastSeenCreatedAt, setLastSeenCreatedAt] = useState(() => sessionStorage.getItem('lastSeenCreatedAt'));
  const refreshingRef = useRef(null);

  const setAuth = useCallback(({ accessToken: nextAccess, refreshToken: nextRefresh, user: nextUser, roles: nextRoles, lastSeenCreatedAt: nextSeen }) => {
    if (nextAccess !== undefined) {
      if (nextAccess) {
        sessionStorage.setItem('accessToken', nextAccess);
        setAccessToken(nextAccess);
      } else {
        sessionStorage.removeItem('accessToken');
        setAccessToken(null);
      }
    }
    if (nextRefresh !== undefined) {
      if (nextRefresh) {
        sessionStorage.setItem('refreshToken', nextRefresh);
        setRefreshToken(nextRefresh);
      } else {
        sessionStorage.removeItem('refreshToken');
        setRefreshToken(null);
      }
    }
    if (nextUser !== undefined) {
      if (nextUser) {
        sessionStorage.setItem('user', JSON.stringify(nextUser));
        setUser(nextUser);
      } else {
        sessionStorage.removeItem('user');
        setUser(null);
      }
    }
    if (nextRoles !== undefined) {
      const value = Array.isArray(nextRoles) ? nextRoles : [];
      sessionStorage.setItem('roles', JSON.stringify(value));
      setRoles(value);
    }
    if (nextSeen !== undefined) {
      if (nextSeen) {
        sessionStorage.setItem('lastSeenCreatedAt', nextSeen);
        setLastSeenCreatedAt(nextSeen);
      } else {
        sessionStorage.removeItem('lastSeenCreatedAt');
        setLastSeenCreatedAt(null);
      }
    }
  }, []);

  const refreshAccessToken = useCallback(async () => {
    if (!refreshToken) return false;
    if (refreshingRef.current) {
      return refreshingRef.current;
    }

    const pending = (async () => {
      try {
        const res = await fetch(`${apiBase}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
        if (!res.ok) throw new Error(`Refresh failed (${res.status})`);
        const data = await res.json();
        setAuth({ accessToken: data.access_token ?? null });
        return true;
      } catch (err) {
        console.warn('Refresh token failed', err);
        setAuth({ accessToken: null, refreshToken: null, user: null, roles: [] });
        return false;
      } finally {
        refreshingRef.current = null;
      }
    })();

    refreshingRef.current = pending;
    return pending;
  }, [apiBase, refreshToken, setAuth]);

  const logout = useCallback(async () => {
    try {
      if (refreshToken) {
        await fetch(`${apiBase}/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });
      }
    } catch (err) {
      console.warn('Logout request failed', err);
    } finally {
      setAuth({ accessToken: null, refreshToken: null, user: null, roles: [], lastSeenCreatedAt: null });
    }
  }, [apiBase, refreshToken, setAuth]);

  const login = useCallback(async (username, password) => {
    const res = await fetch(`${apiBase}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => 'Login failed');
      throw new Error(text || 'Login failed');
    }
    const data = await res.json();
    setAuth({
      accessToken: data.access_token ?? null,
      refreshToken: data.refresh_token ?? null,
      user: data.user ?? null,
      roles: data.roles ?? [],
    });
    return data;
  }, [apiBase, setAuth]);

  const apiFetch = useCallback(async (path, options = {}, { tryRefresh = true } = {}) => {
    const url = path.startsWith('http') ? path : `${apiBase}${path}`;
    const init = { ...options };
    const headers = new Headers(options.headers || {});

    const body = options.body;
    const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
    if (body && !isFormData && typeof body === 'object' && !(body instanceof Blob)) {
      init.body = JSON.stringify(body);
      if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    } else if (body) {
      init.body = body;
    }

    if (accessToken && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${accessToken}`);
    }

    // Add CSRF token for state-changing operations
    const method = (init.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      headers.set('X-CSRF-Token', getCsrfToken());
    }

    init.headers = headers;

    const res = await fetch(url, init);
    if (res.status === 401 && tryRefresh && refreshToken) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        return apiFetch(path, options, { tryRefresh: false });
      }
      await logout();
      throw new Error('Unauthorized');
    }
    return res;
  }, [accessToken, apiBase, logout, refreshAccessToken, refreshToken]);

  const updateLastSeen = useCallback((createdAt) => {
    setAuth({ lastSeenCreatedAt: createdAt ?? null });
  }, [setAuth]);

  // Session timeout - logout after 15 minutes of inactivity
  useSessionTimeout(
    useCallback(() => {
      logout();
    }, [logout]),
    15 * 60 * 1000,
    Boolean(accessToken)
  );

  const value = useMemo(() => ({
    apiBase,
    accessToken,
    refreshToken,
    user,
    roles,
    lastSeenCreatedAt,
    isAuthenticated: Boolean(accessToken),
    setAuth,
    login,
    logout,
    apiFetch,
    updateLastSeen,
  }), [apiBase, accessToken, refreshToken, user, roles, lastSeenCreatedAt, login, logout, apiFetch, updateLastSeen]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}