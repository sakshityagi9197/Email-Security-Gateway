import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../context/AuthContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';

export default function PoliciesPage() {
  const { setPage } = usePage();
  const { apiFetch, roles } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [policies, setPolicies] = useState([]);

  const isAdmin = roles.includes('admin');

  useEffect(() => {
    setPage({
      title: 'Policies',
      breadcrumbs: [{ label: 'Policies' }],
    });
  }, [setPage]);

  useEffect(() => {
    let ignore = false;
    const loadPolicies = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await apiFetch('/policies?limit=5');
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        const data = await res.json();
        if (!ignore) {
          setPolicies(Array.isArray(data.items) ? data.items : []);
        }
      } catch (err) {
        console.error('Failed to load policies', err);
        if (!ignore) setError('Failed to load policies.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };
    loadPolicies();
    return () => {
      ignore = true;
    };
  }, [apiFetch]);

  return (
    <div className="policies-page">
      <div className="card card-outline card-primary">
        <div className="card-header d-flex align-items-center justify-content-between">
          <h3 className="card-title mb-0">Policies</h3>
          {isAdmin && (
            <button type="button" className="btn btn-primary btn-sm" onClick={() => navigate('/policy/new')}>
              <i className="fas fa-plus me-1" />
              New Policy
            </button>
          )}
        </div>
        <div className="card-body p-0">
          {error ? (
            <div className="alert alert-danger m-3 mb-0">{error}</div>
          ) : loading ? (
            <div className="text-muted p-3">Loading policies...</div>
          ) : (
            <div className="table-responsive">
              <table className="table table-hover mb-0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Last Modified</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="text-muted text-center py-4">
                        No policies found
                      </td>
                    </tr>
                  ) : (
                    policies.map((policy) => (
                      <tr
                        key={policy.id}
                        role="button"
                        onClick={() => navigate(`/policy/${policy.id}`)}
                      >
                        <td>{policy.name}</td>
                        <td>
                          <StatusBadge status={policy.status}>{policy.status || ''}</StatusBadge>
                        </td>
                        <td className="text-muted">{policy.last_modified || ''}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}