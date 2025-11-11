import { useEffect, useState, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import { RateLimiter } from '../utils/helpers.js';

export default function LoginPage() {
  const { setPage } = usePage();
  const { login, isAuthenticated } = useAuth();
  const { push } = useToast();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const rateLimiterRef = useRef(new RateLimiter(5, 60000)); // 5 attempts per minute

  useEffect(() => {
    setPage({
      title: 'Sign In',
      breadcrumbs: [{ label: 'Login' }],
    });
  }, [setPage]);

  useEffect(() => {
    if (isAuthenticated) {
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location.state]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');

    // Rate limiting check
    const rateCheck = rateLimiterRef.current.attempt();
    if (!rateCheck.allowed) {
      setError(rateCheck.message);
      push(rateCheck.message, { variant: 'warning', persistent: true });
      return;
    }

    setLoading(true);
    try {
      await login(username.trim(), password);
      rateLimiterRef.current.reset();
      push('Welcome back!', { variant: 'success' });
    } catch (err) {
      console.error('Login failed', err);
      setError('Login failed. Check your credentials and try again.');
      push('Login failed', { variant: 'danger' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* full-viewport background element (fixed) */}
      <div className="login-page" />
      <div className="row justify-content-center">
      <div className="col-12 col-md-6 col-xl-4">
        <div className="card card-primary card-outline">
          <div className="card-body">
            <h2 className="mb-1 text-center">Sign In</h2>
            <p className="text-muted text-center mb-4">Access the AegisMail control center</p>
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label className="form-label" htmlFor="loginUsername">Username</label>
                <input
                  id="loginUsername"
                  className="form-control"
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={loading}
                  required
                />
              </div>
              <div className="mb-4">
                <label className="form-label" htmlFor="loginPassword">Password</label>
                <input
                  id="loginPassword"
                  type="password"
                  className="form-control"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={loading}
                  required
                />
              </div>
              <button type="submit" className="btn btn-primary w-100" disabled={loading}>
                {loading ? 'Signing In...' : 'Sign In'}
              </button>
            </form>
            {error && <div className="text-danger small mt-3">{error}</div>}
          </div>
        </div>
      </div>
    </div>
    </>
  );
}