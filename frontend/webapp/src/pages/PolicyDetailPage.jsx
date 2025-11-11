import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import yaml from 'js-yaml';

import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import { sanitizeHtml } from '../utils/helpers.js';

const EMPTY_POLICY = {
  name: '',
  version: '',
  description: '',
};

function toRuleState(rule) {
  return {
    id: rule?.id || '',
    name: rule?.name || '',
    category: rule?.category || '',
    action: rule?.action || '',
    reasoning: rule?.reasoning || '',
    conditionsText: rule?.conditions ? JSON.stringify(rule.conditions, null, 2) : '',
  };
}

export default function PolicyDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { setPage } = usePage();
  const { apiFetch, roles } = useAuth();
  const { push } = useToast();

  const isNew = id === 'new';
  const isAdmin = roles.includes('admin');

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [policy, setPolicy] = useState(EMPTY_POLICY);
  const [rules, setRules] = useState([]);
  const [status, setStatus] = useState('');

  useEffect(() => {
    const title = isNew ? 'New Policy' : `Policy ${id}`;
    setPage({
      title,
      breadcrumbs: [
        { label: 'Policies', href: '/policies' },
        { label: title },
      ],
    });
  }, [id, isNew, setPage]);

  useEffect(() => {
    if (isNew) {
      setPolicy(EMPTY_POLICY);
      setRules([]);
      setStatus('');
      setLoading(false);
      return;
    }

    let ignore = false;
    const loadPolicy = async () => {
      setLoading(true);
      setError('');
      try {
        const res = await apiFetch(`/policy/${id}`);
        if (!res.ok) throw new Error(`Request failed (${res.status})`);
        const data = await res.json();
        if (ignore) return;
        const parsed = data.parsed || { policy: {}, rules: [] };
        setPolicy({
          name: parsed.policy?.name || '',
          version: parsed.policy?.version || '',
          description: parsed.policy?.description || '',
        });
        setRules(Array.isArray(parsed.rules) ? parsed.rules.map(toRuleState) : []);
        setStatus(data.status || parsed.policy?.status || '');
      } catch (err) {
        console.error('Failed to load policy', err);
        if (!ignore) setError('Failed to load policy.');
      } finally {
        if (!ignore) setLoading(false);
      }
    };

    loadPolicy();
    return () => {
      ignore = true;
    };
  }, [apiFetch, id, isNew]);

  const canEdit = isAdmin;
  const pageTitle = useMemo(() => (isNew ? 'New Policy' : policy.name || `Policy ${id}`), [id, isNew, policy.name]);

  const handlePolicyChange = (field) => (event) => {
    const { value } = event.target;
    setPolicy((prev) => ({ ...prev, [field]: value }));
  };

  const handleRuleChange = (index, field) => (event) => {
    const { value } = event.target;
    setRules((prev) => prev.map((rule, idx) => (idx === index ? { ...rule, [field]: value } : rule)));
  };

  const addRule = () => {
    setRules((prev) => [
      ...prev,
      {
        id: '',
        name: '',
        category: '',
        action: '',
        reasoning: '',
        conditionsText: '',
      },
    ]);
  };

  const removeRule = (index) => {
    setRules((prev) => prev.filter((_, idx) => idx !== index));
  };

  const parseConditions = (text) => {
    const trimmed = (text || '').trim();
    if (!trimmed) return undefined;
    try {
      return JSON.parse(trimmed);
    } catch (jsonErr) {
      try {
        return yaml.load(trimmed);
      } catch (yamlErr) {
        console.warn('Failed to parse rule conditions', { jsonErr, yamlErr });
        throw new Error(`Invalid JSON/YAML: ${jsonErr.message}`);
      }
    }
  };

  const validateRule = (rule, index) => {
    if (!rule.id?.trim()) {
      throw new Error(`Rule #${index + 1}: ID is required`);
    }
    if (!rule.name?.trim()) {
      throw new Error(`Rule #${index + 1}: Name is required`);
    }
    if (!rule.action?.trim()) {
      throw new Error(`Rule #${index + 1}: Action is required`);
    }
    // Validate conditions if provided
    if (rule.conditionsText?.trim()) {
      try {
        parseConditions(rule.conditionsText);
      } catch (err) {
        throw new Error(`Rule #${index + 1}: ${err.message}`);
      }
    }
  };

  const handleSave = async () => {
    if (!canEdit) return;

    // Validate required fields
    if (!policy.name?.trim()) {
      push('Policy name is required', { variant: 'danger', persistent: true });
      return;
    }

    if (!policy.version?.trim()) {
      push('Policy version is required', { variant: 'danger', persistent: true });
      return;
    }

    // Validate rules
    try {
      for (let i = 0; i < rules.length; i++) {
        validateRule(rules[i], i);
      }
    } catch (err) {
      push(err.message, { variant: 'danger', persistent: true });
      return;
    }

    setSaving(true);
    try {
      // Convert policy to YAML format - sanitize text inputs
      const policyData = {
        policy: {
          name: sanitizeHtml(policy.name.trim()),
          version: sanitizeHtml(policy.version.trim()),
          description: sanitizeHtml(policy.description.trim()),
        },
        rules: rules.map((rule) => ({
          id: sanitizeHtml(rule.id.trim()),
          name: sanitizeHtml(rule.name.trim()),
          category: sanitizeHtml(rule.category.trim()),
          action: sanitizeHtml(rule.action.trim()),
          reasoning: sanitizeHtml(rule.reasoning.trim()),
          conditions: parseConditions(rule.conditionsText) || {},
        })),
      };

      // Clean the policy data
      const cleanPolicyData = JSON.parse(JSON.stringify(policyData));
      
      // Create YAML content
      const policyYaml = yaml.dump(cleanPolicyData);

      // Create or update policy
      const method = isNew ? 'POST' : 'PUT';
      const url = isNew ? '/policy' : `/policy/${id}`;
      
      // Create the request payload
      const requestBody = {
        name: cleanPolicyData.policy.name,
        content: policyYaml
      };

      // Send the request
      const res = await apiFetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });
      
      if (!res.ok) {
        const text = await res.text();
        try {
          const errorData = JSON.parse(text);
          throw new Error(errorData.detail || 'Failed to save policy');
        } catch (jsonError) {
          // If it's not JSON, use the raw text
          throw new Error(text || 'Failed to save policy');
        }
      }
      
      const data = await res.json();
      push('Policy saved successfully', { variant: 'success' });
      
      if (isNew) {
        navigate(`/policy/${data.id}`);
      } else {
        // Reload the policy to show updated content
        navigate(0);
      }
    } catch (err) {
      console.error('Save policy failed', err);
      push(err.message || 'Failed to save policy', { variant: 'danger', persistent: true });
    } finally {
      setSaving(false);
    }
  };

  const handleActivate = async () => {
    if (!isAdmin || isNew) return;
    try {
      // First ensure the policy is saved
      if (saving) {
        push('Please wait for the policy to save first', { variant: 'warning' });
        return;
      }

      const res = await apiFetch(`/policy/${id}/activate`, { method: 'PATCH' });
      
      if (!res.ok) {
        const errText = await res.text().catch(() => 'Failed to activate policy');
        throw new Error(errText);
      }

      const data = await res.json();
      if (data.active) {
        push('Policy activated successfully - This is now the enforced policy', { variant: 'success' });
      } else {
        throw new Error('Policy activation failed');
      }

      // Refresh the page to show updated status
      navigate(0);
    } catch (err) {
      console.error('Activate policy failed', err);
      push(err.message || 'Failed to activate policy', { variant: 'danger' });
    }
  };

  return (
    <div className="policy-detail-page">
      <div className="d-flex flex-wrap align-items-center gap-2 mb-3">
        <Link className="btn btn-outline-secondary" to="/policies">
          <i className="fas fa-arrow-left me-1" />
          Back
        </Link>
        <div className="ms-auto d-flex gap-2">
          {canEdit && (
            <button type="button" className="btn btn-primary" onClick={handleSave} disabled={saving}>
              <i className="fas fa-save me-1" />
              {saving ? 'Saving...' : 'Save'}
            </button>
          )}
          {canEdit && !isNew && (
            <button type="button" className="btn btn-success" onClick={handleActivate}>
              <i className="fas fa-play me-1" />
              Activate
            </button>
          )}
        </div>
      </div>

      {error && <div className="alert alert-danger">{error}</div>}
      {loading ? (
        <div className="text-muted">Loading policy...</div>
      ) : (
        <div className="row g-3">
          <div className="col-12 col-lg-4">
            <div className="card card-outline card-primary h-100">
              <div className="card-header">
                <h3 className="card-title mb-0">Policy Details</h3>
              </div>
              <div className="card-body">
                <div className="mb-3">
                                    <label className="form-label" htmlFor="policyName">Name<span className="text-danger">*</span></label>
                  <input
                    id="policyName"
                    type="text"
                    className={`form-control ${!policy.name?.trim() ? 'is-invalid' : ''}`}
                    value={policy.name}
                    onChange={handlePolicyChange('name')}
                    disabled={!canEdit}
                    required
                  />
                  {!policy.name?.trim() && (
                    <div className="invalid-feedback">
                      Policy name is required
                    </div>
                  )}
                </div>
                                <div className="mb-3">
                  <label className="form-label" htmlFor="policyVersion">Version<span className="text-danger">*</span></label>
                  <input
                    id="policyVersion"
                    type="text"
                    className={`form-control ${!policy.version?.trim() ? 'is-invalid' : ''}`}
                    value={policy.version}
                    onChange={handlePolicyChange('version')}
                    disabled={!canEdit}
                    required
                  />
                  {!policy.version?.trim() && (
                    <div className="invalid-feedback">
                      Policy version is required
                    </div>
                  )}
                </div>
                <div className="mb-3">
                  <label className="form-label" htmlFor="policyDescription">Description</label>
                  <textarea
                    id="policyDescription"
                    className="form-control"
                    rows={4}
                    value={policy.description}
                    onChange={handlePolicyChange('description')}
                    readOnly={!canEdit}
                  />
                </div>
                {!isNew && status && (
                  <div className="mb-0 text-muted small">Current status: {status}</div>
                )}
              </div>
            </div>
          </div>

          <div className="col-12 col-lg-8">
            <div className="card card-outline card-secondary">
              <div className="card-header d-flex align-items-center justify-content-between">
                <h3 className="card-title mb-0">Rules</h3>
                {canEdit && (
                  <button type="button" className="btn btn-outline-primary btn-sm" onClick={addRule}>
                    <i className="fas fa-plus me-1" />
                    Add Rule
                  </button>
                )}
              </div>
              <div className="card-body p-0">
                <div className="table-responsive">
                  <table className="table table-bordered align-middle mb-0">
                    <thead>
                      <tr>
                        <th>Rule ID</th>
                        <th>Name</th>
                        <th>Category</th>
                        <th>Condition (JSON/YAML)</th>
                        <th>Action</th>
                        <th>Reasoning</th>
                        {canEdit && <th style={{ width: 60 }}>Actions</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {rules.length === 0 ? (
                        <tr>
                          <td colSpan={canEdit ? 7 : 6} className="text-muted text-center py-4">
                            No rules defined
                          </td>
                        </tr>
                      ) : (
                        rules.map((rule, index) => (
                          <tr key={index}>
                            <td>
                              {canEdit ? (
                                <input
                                  className="form-control form-control-sm"
                                  value={rule.id}
                                  onChange={handleRuleChange(index, 'id')}
                                />
                              ) : (
                                rule.id
                              )}
                            </td>
                            <td>
                              {canEdit ? (
                                <input
                                  className="form-control form-control-sm"
                                  value={rule.name}
                                  onChange={handleRuleChange(index, 'name')}
                                />
                              ) : (
                                rule.name
                              )}
                            </td>
                            <td>
                              {canEdit ? (
                                <input
                                  className="form-control form-control-sm"
                                  value={rule.category}
                                  onChange={handleRuleChange(index, 'category')}
                                />
                              ) : (
                                rule.category
                              )}
                            </td>
                            <td>
                              {canEdit ? (
                                <textarea
                                  className="form-control form-control-sm"
                                  rows={3}
                                  value={rule.conditionsText}
                                  onChange={handleRuleChange(index, 'conditionsText')}
                                />
                              ) : (
                                <pre className="pre mb-0" style={{ whiteSpace: 'pre-wrap' }}>
                                  {rule.conditionsText}
                                </pre>
                              )}
                            </td>
                            <td>
                              {canEdit ? (
                                <input
                                  className="form-control form-control-sm"
                                  value={rule.action}
                                  onChange={handleRuleChange(index, 'action')}
                                />
                              ) : (
                                rule.action
                              )}
                            </td>
                            <td>
                              {canEdit ? (
                                <input
                                  className="form-control form-control-sm"
                                  value={rule.reasoning}
                                  onChange={handleRuleChange(index, 'reasoning')}
                                />
                              ) : (
                                rule.reasoning
                              )}
                            </td>
                            {canEdit && (
                              <td className="text-center">
                                <button
                                  type="button"
                                  className="btn btn-outline-danger btn-sm"
                                  onClick={() => removeRule(index)}
                                >
                                  <i className="fas fa-trash" />
                                </button>
                              </td>
                            )}
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}