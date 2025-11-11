import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { useAuth } from '../context/AuthContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import ConfirmDialog from '../components/ConfirmDialog.jsx';
import { parseSender, statusLabel } from '../utils/formatters.js';

const FOLDERS = [
  { value: 'quarantine', label: 'Quarantine' },
  { value: 'blocked', label: 'Blocked' },
  { value: 'all', label: 'All' },
];

export default function EmailsPage() {
  const { setPage } = usePage();
  const { apiFetch, roles } = useAuth();
  const { push } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();

  const folder = searchParams.get('folder') || 'quarantine';
  const folderLabel = FOLDERS.find((item) => item.value === folder)?.label || 'Quarantine';

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [emails, setEmails] = useState([]);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const isAdmin = roles.includes('admin');

  useEffect(() => {
    setPage({
      title: 'Emails',
      breadcrumbs: [
        { label: 'Emails', href: '/emails' },
        { label: folderLabel },
      ],
    });
  }, [folderLabel, setPage]);

  useEffect(() => {
    let ignore = false;

    const loadEmails = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await apiFetch(`/emails?folder=${encodeURIComponent(folder)}&page=1&page_size=50&sort=-created_at`);
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        const data = await res.json();
        if (!ignore) {
          setEmails(Array.isArray(data.items) ? data.items : []);
        }
      } catch (err) {
        console.error('Failed to load emails', err);
        if (!ignore) setError('Failed to load emails.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    loadEmails();

    const handler = () => {
      loadEmails();
    };
    window.addEventListener('emails:refresh', handler);

    return () => {
      ignore = true;
      window.removeEventListener('emails:refresh', handler);
    };
  }, [apiFetch, folder]);

  const handleFolderChange = (event) => {
    const next = event.target.value;
    if (next === 'quarantine') {
      setSearchParams({});
    } else {
      setSearchParams({ folder: next });
    }
  };

  const handleClearFolder = async () => {
    if (!isAdmin) return;
    try {
      if (folder === 'all') {
        const resQuarantine = await apiFetch('/emails/clear', { method: 'POST', body: { folder: 'quarantine' } });
        const resBlocked = await apiFetch('/emails/clear', { method: 'POST', body: { folder: 'blocked' } });
        if (!resQuarantine.ok || !resBlocked.ok) {
          throw new Error('Failed to clear folders');
        }
      } else {
        const res = await apiFetch('/emails/clear', { method: 'POST', body: { folder } });
        if (!res.ok) throw new Error('Failed to clear folder');
      }
      push('Folder cleared', { variant: 'success' });
      window.dispatchEvent(new CustomEvent('emails:refresh'));
      setConfirmOpen(false);
    } catch (err) {
      console.error('Clear folder failed', err);
      push('Failed to clear folder', { variant: 'danger' });
      setConfirmOpen(false);
    }
  };

  return (
    <div className="emails-page">
      <div className="card card-outline card-secondary">
        <div className="card-header">
          <div className="row g-3 align-items-end">
            <div className="col-sm-6 col-lg-4">
              <label className="form-label" htmlFor="folderSelect">Folder</label>
              <select id="folderSelect" className="form-select" value={folder} onChange={handleFolderChange}>
                {FOLDERS.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="col-sm-6 col-lg-8 text-sm-end">
              {isAdmin && (
                <button type="button" className="btn btn-outline-danger" onClick={() => setConfirmOpen(true)}>
                  <i className="fas fa-broom me-1" />
                  Clear Folder
                </button>
              )}
            </div>
          </div>
        </div>
        <div className="card-body p-0">
          {error ? (
            <div className="alert alert-danger m-3 mb-0">{error}</div>
          ) : loading ? (
            <div className="text-muted p-3">Loading emails...</div>
          ) : (
            <div className="table-responsive">
              <table className="table table-striped mb-0">
                <thead>
                  <tr>
                    <th>Subject</th>
                    <th>From</th>
                    <th>Time</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {emails.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="text-muted text-center py-4">
                        No emails in this folder
                      </td>
                    </tr>
                  ) : (
                    emails.map((email) => {
                      const { name, email: senderEmail } = parseSender(email.from);
                      return (
                        <tr key={email.id}>
                          <td>
                            <Link to={`/emails/${email.id}`}>{email.subject || ''}</Link>
                          </td>
                          <td>
                            <span>{name || senderEmail || ''}</span>
                            {senderEmail && <span className="sender-email"> &lt;{senderEmail}&gt;</span>}
                          </td>
                          <td className="text-muted">{email.created_at || ''}</td>
                          <td>
                            <StatusBadge status={email.final_decision}>{statusLabel(email.final_decision)}</StatusBadge>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleClearFolder}
        title="Clear Folder"
        message={`Are you sure you want to clear the ${folder === 'all' ? 'quarantine and blocked folders' : `${folder} folder`}? This action cannot be undone.`}
        confirmText="Clear"
        confirmVariant="danger"
        requireTyping={true}
        typeText="CLEAR"
      />
    </div>
  );
}