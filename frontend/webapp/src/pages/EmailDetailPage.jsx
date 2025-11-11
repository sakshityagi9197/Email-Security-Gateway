import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import ConfirmDialog from '../components/ConfirmDialog.jsx';
import { formatBytes } from '../utils/formatters.js';

export default function EmailDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { setPage } = usePage();
  const { apiFetch, roles } = useAuth();
  const { push } = useToast();

  const canManage = roles.includes('admin') || roles.includes('analyst');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState(null);
  const [attachments, setAttachments] = useState([]);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);

  const iframeRef = useRef(null);

  useEffect(() => {
    setPage({
      title: `Email ${id}`,
      breadcrumbs: [
        { label: 'Emails', href: '/emails' },
        { label: `Email ${id}` },
      ],
    });
  }, [id, setPage]);

  useEffect(() => {
    let ignore = false;

    const loadMessage = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await apiFetch(`/emails/${id}`);
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        const data = await res.json();
        if (ignore) return;
        setMessage(data);
        setPage({
          title: data.email?.subject || `Email ${id}`,
          breadcrumbs: [
            { label: 'Emails', href: '/emails' },
            { label: data.email?.subject || `Email ${id}` },
          ],
        });

        const attachmentRes = await apiFetch(`/emails/${id}/attachments`);
        if (attachmentRes.ok) {
          const attachmentData = await attachmentRes.json();
          if (!ignore) setAttachments(Array.isArray(attachmentData.items) ? attachmentData.items : []);
        }
      } catch (err) {
        console.error('Failed to load email', err);
        if (!ignore) setError('Failed to load email.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    loadMessage();
    return () => {
      ignore = true;
    };
  }, [apiFetch, id, setPage]);

  useEffect(() => {
    if (!message || !iframeRef.current) return;
    const htmlSafe = message.body?.html_safe || '';
    const fallback = '<div style="font-family: system-ui; padding: 8px; color: #666;">(no HTML body)</div>';
    // Add CSP meta tag for additional security in iframe
    const htmlWithCsp = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; font-src data:;">
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 16px; word-wrap: break-word; }
        </style>
      </head>
      <body>${(htmlSafe || '').trim() || fallback}</body>
      </html>
    `;
    iframeRef.current.srcdoc = htmlWithCsp;
  }, [message]);

  const handleForward = async () => {
    try {
      const res = await apiFetch('/forward', { method: 'POST', body: { id } });
      if (!res.ok) throw new Error(`Forward failed (${res.status})`);
      push('Email forwarded', { variant: 'success' });
    } catch (err) {
      console.error('Forward failed', err);
      push('Failed to forward email', { variant: 'danger' });
    }
  };

  const handleDelete = async () => {
    try {
      const res = await apiFetch(`/emails/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`Delete failed (${res.status})`);
      push('Email deleted', { variant: 'success' });
      setConfirmDeleteOpen(false);
      navigate('/emails');
    } catch (err) {
      console.error('Delete failed', err);
      push('Failed to delete email', { variant: 'danger' });
      setConfirmDeleteOpen(false);
    }
  };

  if (loading) {
    return <div className="text-muted">Loading email...</div>;
  }

  if (error) {
    return <div className="alert alert-danger">{error}</div>;
  }

  if (!message) {
    return <div className="text-muted">Email not found.</div>;
  }

  const subject = message.email?.subject || `Email ${id}`;
  const reasons = Array.isArray(message.reasons) ? message.reasons : [];

  return (
    <div className="email-detail-page">
      <div className="d-flex flex-wrap align-items-center gap-2 mb-3">
        <Link className="btn btn-outline-secondary" to="/emails">
          <i className="fas fa-arrow-left me-1" />
          Back
        </Link>
        <div className="ms-auto d-flex gap-2">
          {canManage && (
            <button type="button" className="btn btn-outline-primary" onClick={handleForward}>
              <i className="fas fa-share me-1" />
              Forward
            </button>
          )}
          {canManage && (
            <button type="button" className="btn btn-outline-danger" onClick={() => setConfirmDeleteOpen(true)}>
              <i className="fas fa-trash me-1" />
              Delete
            </button>
          )}
        </div>
      </div>

      <div className="row g-3">
        <div className="col-12">
          <div className="card card-outline card-secondary">
            <div className="card-body">
              <h2 className="h5 mb-2">
                {subject}
                <span className="ms-2">
                  <StatusBadge status={message.final_decision}>{message.final_decision || ''}</StatusBadge>
                </span>
              </h2>
              <div className="text-muted mb-2">
                <div>
                  <strong>From:</strong> {message.email?.from || ''}
                </div>
                <div>
                  <strong>Time:</strong> {message.created_at || ''}
                </div>
              </div>
              <h3 className="h6">Reason</h3>
              {reasons.length === 0 ? (
                <div className="text-muted">No reasons provided</div>
              ) : (
                <ul className="mb-0">
                  {reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>

        <div className="col-12">
          <div className="card card-outline card-info details-card">
            <div className="card-body">
              <h3 className="h6">Headers</h3>
              <details>
                <summary>Show ({message.headers ? Object.keys(message.headers).length : 0})</summary>
                <pre className="pre mt-2" style={{ maxHeight: 240, overflow: 'auto' }}>
{JSON.stringify(message.headers || {}, null, 2)}
                </pre>
              </details>
            </div>
          </div>
        </div>

        <div className="col-12">
          <div className="card card-outline card-primary">
            <div className="card-body">
              <h3 className="h6">Email Body</h3>
              <h4 className="h6 text-muted">Rendered HTML</h4>
              <div className="mail-frame-wrap">
                <iframe
                  ref={iframeRef}
                  className="mail-frame"
                  sandbox="allow-same-origin"
                  title="Email HTML preview"
                />
              </div>
              <details className="mt-3">
                <summary>Show Text Version</summary>
                <pre className="pre">{message.body?.text || ''}</pre>
              </details>
            </div>
          </div>
        </div>

        <div className="col-12">
          <div className="card card-outline card-secondary">
            <div className="card-body">
              <h3 className="h6">Attachments</h3>
              {attachments.length === 0 ? (
                <div className="text-muted">No attachments</div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-striped align-middle mb-0">
                    <thead>
                      <tr>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Malicious</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attachments.map((attachment) => (
                        <tr key={attachment.id || attachment.filename}>
                          <td>{attachment.filename}</td>
                          <td>{formatBytes(attachment.size)}</td>
                          <td>{attachment.is_malicious ? 'Yes' : 'No'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <ConfirmDialog
        isOpen={confirmDeleteOpen}
        onClose={() => setConfirmDeleteOpen(false)}
        onConfirm={handleDelete}
        title="Delete Email"
        message={`Are you sure you want to delete this email? This action cannot be undone.`}
        confirmText="Delete"
        confirmVariant="danger"
        requireTyping={true}
        typeText="DELETE"
      />
    </div>
  );
}