import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useRef } from 'react';
import AegisLogo from '../Aegis-logo.png';

import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import { usePage } from '../context/PageContext.jsx';

import ToastStack from './ToastStack.jsx';
import NotificationWatcher from './NotificationWatcher.jsx';
import { validateFileSize, formatBytes } from '../utils/helpers.js';

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/policies', label: 'Policies' },
  { to: '/emails', label: 'Emails' },
  { to: '/settings', label: 'Settings' },
];

function Breadcrumbs({ items }) {
  if (!items || !items.length) return null;
  const enriched = items[0]?.label === 'Home'
    ? items
    : [{ label: 'Home', href: '/' }, ...items];
  return (
    <ol className="breadcrumb mb-0">
      {enriched.map((item, idx) => {
        const isLast = idx === enriched.length - 1;
        if (isLast) {
          return (
            <li key={idx} className="breadcrumb-item active" aria-current="page">
              {item.label}
            </li>
          );
        }
        return (
          <li key={idx} className="breadcrumb-item">
            {item.href ? <NavLink to={item.href}>{item.label}</NavLink> : item.label}
          </li>
        );
      })}
    </ol>
  );
}

export default function Layout() {
  const { pageState } = usePage();
  const { isAuthenticated, user, roles, logout, apiFetch } = useAuth();
  const { push, dismiss } = useToast();
  const fileInputRef = useRef(null);
  const navigate = useNavigate();
  const location = useLocation();

  const handleRefresh = async () => {
    try {
      await apiFetch('/sync', { method: 'POST' });
      push('Synced successfully', { variant: 'success' });
    } catch (err) {
      console.error('Sync failed', err);
      push('Sync failed', { variant: 'danger' });
    }
  };

  const handleUploadClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
      fileInputRef.current.click();
    }
  };

  const handleEmlUpload = async (files) => {
    if (!files || !files.length) return;
    const slice = files.slice(0, 10);
    let success = 0;

    for (let index = 0; index < slice.length; index += 1) {
      const file = slice[index];
      const toastId = push(`Uploading ${index + 1}/${slice.length}: ${file.name}`, { persistent: true });
      try {
        const formData = new FormData();
        formData.append('file', file, file.name);
        const res = await apiFetch('/analyze/upload', {
          method: 'POST',
          body: formData,
          headers: {},
        });
        if (!res.ok) {
          const text = await res.text().catch(() => 'Upload failed');
          throw new Error(text);
        }
        const data = await res.json();
        const subj = data.email?.subject || '(no subject)';
        const decision = data.final_decision || 'N/A';
        const score = data.policy?.threat_score ?? '-';
        push(`Analyzed: ${subj} -> ${decision} (score: ${score})`, { variant: 'info' });
        success += 1;
      } catch (err) {
        console.error('Upload failed', err);
        push(`Failed to upload ${file.name}`, { variant: 'danger' });
      } finally {
        dismiss(toastId);
      }
    }

    if (success > 0 && !location.pathname.startsWith('/emails')) {
      navigate('/emails');
    }
  };

  const handleFileChange = (event) => {
    const allFiles = Array.from(event.target.files || []);

    // Filter and validate .eml files
    const validFiles = [];
    for (const file of allFiles) {
      if (!file || !file.name) continue;

      // Check file extension
      if (!file.name.toLowerCase().endsWith('.eml')) {
        push(`${file.name}: Not an .eml file`, { variant: 'warning' });
        continue;
      }

      // Validate file size
      const sizeValidation = validateFileSize(file, 25);
      if (!sizeValidation.valid) {
        push(`${file.name}: ${sizeValidation.message}`, { variant: 'danger' });
        continue;
      }

      validFiles.push(file);
    }

    if (!validFiles.length) {
      push('No valid .eml files selected', { variant: 'warning' });
      return;
    }

    handleEmlUpload(validFiles);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="wrapper">
      {isAuthenticated && (
        <nav className="main-header navbar navbar-expand-lg navbar-dark bg-gradient-dark">
          <div className="container-fluid">
              <NavLink className="navbar-brand d-flex align-items-center gap-2" to="/dashboard">
                <img src={AegisLogo} alt="Site Logo" style={{ height: 35 }} />
                <span className="fw-semibold">Email Security Gateway</span>
              </NavLink>
            <button
              className="navbar-toggler"
              type="button"
              data-bs-toggle="collapse"
              data-bs-target="#navbarContent"
              aria-controls="navbarContent"
              aria-expanded="false"
              aria-label="Toggle navigation"
            >
              <span className="navbar-toggler-icon" />
            </button>
            <div className="collapse navbar-collapse" id="navbarContent">
              <ul className="navbar-nav me-auto mb-2 mb-lg-0">
                {NAV_ITEMS.map((item) => (
                  <li className="nav-item" key={item.to}>
                    <NavLink
                      to={item.to}
                      className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
                    >
                      {item.label}
                    </NavLink>
                  </li>
                ))}
              </ul>
              <div className="d-flex align-items-center gap-2">
                <button type="button" className="btn btn-sm btn-outline-light" onClick={handleRefresh} title="Refresh">
                  <i className="fas fa-rotate" />
                </button>
                <button type="button" className="btn btn-sm btn-outline-light" onClick={handleUploadClick} title="Upload .eml">
                  <i className="fas fa-upload" />
                </button>
                <span className="badge bg-light text-dark" title={`Roles: ${roles.join(', ') || 'none'}`}>
                  {user?.username || 'user'}
                </span>
                <button type="button" className="btn btn-sm btn-danger" onClick={handleLogout}>
                  Logout
                </button>
              </div>
            </div>
          </div>
        </nav>
      )}

      <div className="content-wrapper">
        <div className="content-header">
          <div className="container-fluid">
            <div className="d-flex align-items-center justify-content-between">
              <h1 className="m-0 fs-3">{pageState.title || 'Welcome'}</h1>
              <nav aria-label="breadcrumb">
                <Breadcrumbs items={pageState.breadcrumbs} />
              </nav>
            </div>
          </div>
        </div>
        <section className="content">
          <div className="container-fluid pb-4">
            <Outlet />
          </div>
        </section>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        className="d-none"
        accept=".eml"
        multiple
        onChange={handleFileChange}
      />

      <ToastStack />
      <NotificationWatcher />
    </div>
  );
}