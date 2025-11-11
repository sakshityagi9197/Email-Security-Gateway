import { createContext, useCallback, useContext, useMemo, useState } from 'react';

const PageContext = createContext(null);
const DEFAULT_BREADCRUMBS = [{ label: 'Home', href: '/' }];

export function PageProvider({ children }) {
  const [pageState, setPageState] = useState({
    title: 'Welcome',
    breadcrumbs: DEFAULT_BREADCRUMBS,
  });

  const setPage = useCallback((next) => {
    setPageState({
      title: next?.title ?? 'Welcome',
      breadcrumbs: Array.isArray(next?.breadcrumbs) && next.breadcrumbs.length
        ? next.breadcrumbs
        : DEFAULT_BREADCRUMBS,
    });
  }, []);

  const value = useMemo(() => ({ pageState, setPage }), [pageState, setPage]);

  return <PageContext.Provider value={value}>{children}</PageContext.Provider>;
}

export function usePage() {
  const ctx = useContext(PageContext);
  if (!ctx) throw new Error('usePage must be used within PageProvider');
  return ctx;
}