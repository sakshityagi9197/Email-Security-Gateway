import { useEffect } from 'react';
import { Link } from 'react-router-dom';

import { usePage } from '../context/PageContext.jsx';

export default function NotFoundPage() {
  const { setPage } = usePage();

  useEffect(() => {
    setPage({
      title: 'Not Found',
      breadcrumbs: [{ label: 'Not Found' }],
    });
  }, [setPage]);

  return (
    <div className="text-center py-5">
      <h2 className="mb-3">Page not found</h2>
      <p className="text-muted mb-4">The page you are looking for does not exist.</p>
      <Link className="btn btn-primary" to="/">Go home</Link>
    </div>
  );
}