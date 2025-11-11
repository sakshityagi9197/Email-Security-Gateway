import { useEffect, useState } from 'react';

import { useAuth } from '../context/AuthContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import PasswordStrengthMeter from '../components/PasswordStrengthMeter.jsx';
import { validatePasswordStrength } from '../utils/helpers.js';

export default function SettingsPage() {
  const { setPage } = usePage();
  const { apiFetch, roles } = useAuth();
  const { push } = useToast();

  const [loading, setLoading] = useState(true);
  const [blockedAlert, setBlockedAlert] = useState(false);
  const [quarantineAlert, setQuarantineAlert] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [savingToggles, setSavingToggles] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const [error, setError] = useState('');

  const isAdmin = roles.includes('admin');

  useEffect(() => {
    setPage({
      title: 'Settings',
      breadcrumbs: [{ label: 'Settings' }],
    });
  }, [setPage]);

  useEffect(() => {
    let ignore = false;

    const loadSettings = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await apiFetch('/settings');
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        const data = await res.json();
        if (!ignore) {
          setBlockedAlert(Boolean(data.alerts_blocked));
          setQuarantineAlert(Boolean(data.notifications_quarantine));
        }
      } catch (err) {
        console.error('Failed to load settings', err);
        if (!ignore) setError('Failed to load settings.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    loadSettings();
    return () => {
      ignore = true;
    };
  }, [apiFetch]);

  const handleSaveToggles = async () => {
    if (!isAdmin) {
      push('Admin role required to update notifications', { variant: 'warning' });
      return;
    }
    setSavingToggles(true);
    try {
      const blockedRes = await apiFetch('/settings/alerts/blocked', {
        method: 'PUT',
        body: { value: blockedAlert },
      });
      const quarantineRes = await apiFetch('/settings/notifications/quarantine', {
        method: 'PUT',
        body: { value: quarantineAlert },
      });
      if (!blockedRes.ok || !quarantineRes.ok) {
        throw new Error('Failed to save preferences');
      }
      push('Notification settings saved', { variant: 'success' });
    } catch (err) {
      console.error('Save toggles failed', err);
      push('Failed to save notification settings', { variant: 'danger' });
    } finally {
      setSavingToggles(false);
    }
  };

  const handleChangePassword = async () => {
    if (!currentPassword || !newPassword || !confirmPassword) {
      push('Enter all password fields', { variant: 'warning' });
      return;
    }

    // Validate password strength
    const validation = validatePasswordStrength(newPassword);
    if (!validation.valid) {
      push(validation.message, { variant: 'danger', persistent: true });
      return;
    }

    // Check passwords match
    if (newPassword !== confirmPassword) {
      push('New passwords do not match', { variant: 'danger' });
      return;
    }

    setChangingPassword(true);
    try {
      const res = await apiFetch('/settings/change-password', {
        method: 'POST',
        body: {
          current_password: currentPassword,
          new_password: newPassword,
          confirm_new_password: confirmPassword,
        },
      });
      if (!res.ok) throw new Error('Change password failed');
      push('Password changed successfully', { variant: 'success' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      console.error('Change password failed', err);
      push('Failed to change password', { variant: 'danger' });
    } finally {
      setChangingPassword(false);
    }
  };

  return (
    <div className="settings-page">
      {error && <div className="alert alert-danger">{error}</div>}
      {loading ? (
        <div className="text-muted">Loading settings...</div>
      ) : (
        <div className="row g-3">
          <div className="col-12 col-lg-6">
            <div className="card card-outline card-primary h-100">
              <div className="card-header">
                <h3 className="card-title mb-0">Notifications</h3>
              </div>
              <div className="card-body">
                <div className="form-check form-switch mb-3">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id="blockedToggle"
                    checked={blockedAlert}
                    onChange={(event) => setBlockedAlert(event.target.checked)}
                  />
                  <label className="form-check-label" htmlFor="blockedToggle">
                    Blocked Email Alerts
                  </label>
                </div>
                <div className="form-check form-switch mb-4">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id="quarantineToggle"
                    checked={quarantineAlert}
                    onChange={(event) => setQuarantineAlert(event.target.checked)}
                  />
                  <label className="form-check-label" htmlFor="quarantineToggle">
                    Quarantine Notifications
                  </label>
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleSaveToggles}
                  disabled={savingToggles}
                >
                  {savingToggles ? 'Saving...' : 'Save'}
                </button>
              </div>
            </div>
          </div>

          <div className="col-12 col-lg-6">
            <div className="card card-outline card-secondary h-100">
              <div className="card-header">
                <h3 className="card-title mb-0">Change Password</h3>
              </div>
              <div className="card-body">
                <div className="mb-3">
                  <label className="form-label" htmlFor="currentPassword">Current Password</label>
                  <input
                    id="currentPassword"
                    type="password"
                    className="form-control"
                    autoComplete="current-password"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                  />
                </div>
                <div className="mb-3">
                  <label className="form-label" htmlFor="newPassword">New Password</label>
                  <input
                    id="newPassword"
                    type="password"
                    className="form-control"
                    autoComplete="new-password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    minLength={12}
                  />
                  <PasswordStrengthMeter password={newPassword} />
                  <small className="form-text text-muted">
                    Minimum 12 characters, including uppercase, lowercase, number, and special character
                  </small>
                </div>
                <div className="mb-3">
                  <label className="form-label" htmlFor="confirmPassword">Confirm New Password</label>
                  <input
                    id="confirmPassword"
                    type="password"
                    className="form-control"
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                  />
                </div>
                <button
                  type="button"
                  className="btn btn-outline-primary"
                  onClick={handleChangePassword}
                  disabled={changingPassword}
                >
                  {changingPassword ? 'Changing...' : 'Change Password'}
                </button>
              </div>
            </div>
          </div>

          <div className="col-12">
            <div className="card card-outline card-light">
              <div className="card-body">
                <h3 className="card-title mb-2">Spam Detection Level</h3>
                <div className="text-muted">Coming soon</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}