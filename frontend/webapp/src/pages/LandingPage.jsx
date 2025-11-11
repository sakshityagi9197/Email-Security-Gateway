import { useEffect } from 'react';
import { Link } from 'react-router-dom';

import { usePage } from '../context/PageContext.jsx';

export default function LandingPage() {
  const { setPage } = usePage();

  useEffect(() => {
    setPage({
      title: 'Welcome',
      breadcrumbs: [{ label: 'Welcome' }],
    });
  }, [setPage]);

  return (
    <div className="row justify-content-center">
      <div className="col-12 col-md-6 col-lg-4">
        <div className="card card-primary card-outline text-center">
          <div className="card-body">
            <h1 className="h3 mb-2">Email Security Gateway</h1>
            <p className="text-muted mb-4">Secure. Monitor. Act.</p>
            <Link className="btn btn-primary" to="/login">
              <i className="fas fa-shield-alt me-2" />
              Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}