import { useEffect, useMemo, useRef, useState, useCallback, memo } from 'react';
import { Link } from 'react-router-dom';
import Chart from 'chart.js/auto';

import { useAuth } from '../context/AuthContext.jsx';
import { usePage } from '../context/PageContext.jsx';
import { useToast } from '../context/ToastContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { formatNumber, parseSender, statusLabel } from '../utils/formatters.js';
import { useDebounce } from '../hooks/useDebounce.js';

const METRIC_CARDS = [
  { label: 'Total Emails', key: 'total_emails', fallbackKey: 'total', color: 'bg-info', icon: 'fa-envelope-open-text' },
  { label: 'Quarantined', key: 'quarantined', color: 'bg-warning', icon: 'fa-inbox' },
  { label: 'Blocked', key: 'blocked', color: 'bg-danger', icon: 'fa-ban' },
  { label: 'Passed', key: 'passed', color: 'bg-success', icon: 'fa-check-circle' },
];

const DashboardMetrics = memo(function DashboardMetrics({ metrics }) {
  if (!metrics) return null;
  return (
    <div className="row g-3">
      {METRIC_CARDS.map((card) => {
        const value = metrics[card.key] ?? metrics[card.fallbackKey] ?? 0;
        return (
          <div className="col-12 col-sm-6 col-lg-3" key={card.label}>
            <div className={`small-box ${card.color}`}>
              <div className="inner">
                <h3>{formatNumber(value)}</h3>
                <p>{card.label}</p>
              </div>
              <div className="icon">
                <i className={`fas ${card.icon}`} />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
});

const RecentTable = memo(function RecentTable({ items }) {
  if (!items || !items.length) {
    return (
      <div className="table-responsive">
        <table className="table table-striped mb-0">
          <tbody>
            <tr>
              <td className="text-muted text-center py-4">No activity yet</td>
            </tr>
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="table-responsive">
      <table className="table table-striped mb-0">
        <thead>
          <tr>
            <th>Sender</th>
            <th>Subject</th>
            <th>Status</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const { name, email } = parseSender(item.sender);
            return (
              <tr key={item.id}>
                <td>
                  <span>{name || email || ''}</span>
                  {email && <span className="sender-email"> &lt;{email}&gt;</span>}
                </td>
                <td>
                  <Link to={`/emails/${item.id}`}>{item.subject || ''}</Link>
                </td>
                <td>
                  <StatusBadge status={item.status}>{statusLabel(item.status)}</StatusBadge>
                </td>
                <td className="text-muted">{item.time || ''}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
});

export default function DashboardPage() {
  const { setPage } = usePage();
  const { apiFetch } = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [metrics, setMetrics] = useState(null);
  const [graph, setGraph] = useState({ labels: [], total: [], malicious: [] });
  const [recent, setRecent] = useState([]);
  // Auto-refresh / autosync settings (enabled by default)
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(() => {
    try {
      // default to true for new installations; keep user's explicit setting if present
      return JSON.parse(localStorage.getItem('dashboard:autorefresh') || 'true');
    } catch (e) {
      return true;
    }
  });
  const [autoRefreshInterval, setAutoRefreshInterval] = useState(() => {
    try {
      return Number(localStorage.getItem('dashboard:autorefresh_interval') || '30');
    } catch (e) {
      return 30;
    }
  });
  // keep a separate string state for the input so typing doesn't coerce to number mid-edit
  const [autoRefreshIntervalInput, setAutoRefreshIntervalInput] = useState(() => {
    try {
      return String(localStorage.getItem('dashboard:autorefresh_interval') || String(30));
    } catch (e) {
      return String(30);
    }
  });

  const { push } = useToast();
  const isInitialFetch = useRef(true);
  const [refreshing, setRefreshing] = useState(false);

  const totalCanvasRef = useRef(null);
  const rateCanvasRef = useRef(null);
  const totalChartRef = useRef(null);
  const rateChartRef = useRef(null);

  // Debounce the interval input
  const debouncedInterval = useDebounce(autoRefreshIntervalInput, 500);

  useEffect(() => {
    setPage({
      title: 'Dashboard',
      breadcrumbs: [{ label: 'Dashboard' }],
    });
  }, [setPage]);

  // Apply debounced interval
  useEffect(() => {
    const parsed = parseInt(debouncedInterval, 10);
    const finalVal = Math.max(5, Number.isFinite(parsed) ? parsed : 30);
    if (finalVal !== autoRefreshInterval) {
      setAutoRefreshInterval(finalVal);
      try {
        localStorage.setItem('dashboard:autorefresh_interval', String(finalVal));
      } catch (err) {}
    }
  }, [debouncedInterval]);

  useEffect(() => {
    let ignore = false;

    const fetchData = async (fromAutoRefresh = false) => {
      setLoading(true);
      setError('');
      if (fromAutoRefresh) {
        // mark that an automated refresh is occurring (brief spinner)
        try {
          setRefreshing(true);
        } catch (e) {}
      }
      try {
        const metricsRes = await apiFetch('/dashboard/metrics');
        const metricsJson = await metricsRes.json();
        if (ignore) return;
        setMetrics(metricsJson || {});

        const now = new Date();
        const from = new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString();
        const to = now.toISOString();
        const graphRes = await apiFetch(`/dashboard/graph?series=both&date_from=${encodeURIComponent(from)}&date_to=${encodeURIComponent(to)}`);
        const graphJson = await graphRes.json();
        if (ignore) return;
        setGraph({
          labels: graphJson.labels || [],
          total: graphJson.total || [],
          malicious: graphJson.malicious || [],
        });

        const recentRes = await apiFetch('/dashboard/recent');
        const recentJson = await recentRes.json();
        if (ignore) return;
        setRecent(Array.isArray(recentJson) ? recentJson : []);
      } catch (err) {
        console.error('Dashboard fetch failed', err);
        if (!ignore) setError('Failed to load dashboard data.');
      } finally {
        if (!ignore) setLoading(false);
        if (fromAutoRefresh) {
          // short delay to keep spinner visible briefly
          setTimeout(() => {
            try { setRefreshing(false); } catch (e) {}
          }, 1100);

          // show a brief toast so it's clear a refresh fired (use short duration)
          try {
            push('Dashboard refreshed', { variant: 'info', duration: 2000 });
          } catch (e) {}
        }
      }
    };

  // initial fetch
  fetchData();

    // auto-refresh interval (seconds) if enabled
    let timer = null;
    if (autoRefreshEnabled) {
      timer = setInterval(() => {
        fetchData(true);
      }, Math.max(5, Number(autoRefreshInterval) || 30) * 1000);
    }

    return () => {
      ignore = true;
      if (timer) clearInterval(timer);
    };
  }, [apiFetch, autoRefreshEnabled, autoRefreshInterval]);

  const rateSeries = useMemo(() => {
    const { labels, total, malicious } = graph;
    if (!labels.length) return [];
    return labels.map((_, index) => {
      const totalCount = Number(total[index] || 0);
      const maliciousCount = Number(malicious[index] || 0);
      if (totalCount <= 0) return 0;
      return Math.round((maliciousCount / totalCount) * 1000) / 10;
    });
  }, [graph]);

  useEffect(() => {
    if (!totalCanvasRef.current) return undefined;
    if (!graph.labels.length) {
      if (totalChartRef.current) {
        totalChartRef.current.destroy();
        totalChartRef.current = null;
      }
      return undefined;
    }

    // Update existing chart instead of destroying and recreating
    if (totalChartRef.current) {
      totalChartRef.current.data.labels = graph.labels;
      totalChartRef.current.data.datasets[0].data = graph.total;
      totalChartRef.current.update('none'); // Update without animation for better performance
    } else {
      totalChartRef.current = new Chart(totalCanvasRef.current, {
        type: 'line',
        data: {
          labels: graph.labels,
          datasets: [
            {
              label: 'Total Volume',
              data: graph.total,
              borderColor: '#818cf8',
              backgroundColor: 'rgba(129, 140, 248, 0.2)',
              tension: 0.3,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: {
                color: '#cbd5e1'
              }
            }
          },
          scales: {
            x: {
              ticks: { color: '#94a3b8' },
              grid: { color: 'rgba(51, 65, 85, 0.5)' }
            },
            y: {
              beginAtZero: true,
              ticks: { color: '#94a3b8' },
              grid: { color: 'rgba(51, 65, 85, 0.5)' }
            },
          },
        },
      });
    }

    return () => {
      if (totalChartRef.current) {
        totalChartRef.current.destroy();
        totalChartRef.current = null;
      }
    };
  }, [graph.labels, graph.total]);

  useEffect(() => {
    if (!rateCanvasRef.current) return undefined;
    if (!graph.labels.length) {
      if (rateChartRef.current) {
        rateChartRef.current.destroy();
        rateChartRef.current = null;
      }
      return undefined;
    }

    // Update existing chart instead of destroying and recreating
    if (rateChartRef.current) {
      rateChartRef.current.data.labels = graph.labels;
      rateChartRef.current.data.datasets[0].data = rateSeries;
      rateChartRef.current.update('none'); // Update without animation for better performance
    } else {
      rateChartRef.current = new Chart(rateCanvasRef.current, {
        type: 'line',
        data: {
          labels: graph.labels,
          datasets: [
            {
              label: 'Malicious %',
              data: rateSeries,
              borderColor: '#ef4444',
              backgroundColor: 'rgba(239, 68, 68, 0.2)',
              tension: 0.3,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: {
                color: '#cbd5e1'
              }
            }
          },
          scales: {
            x: {
              ticks: { color: '#94a3b8' },
              grid: { color: 'rgba(51, 65, 85, 0.5)' }
            },
            y: {
              beginAtZero: true,
              max: 100,
              ticks: { color: '#94a3b8' },
              grid: { color: 'rgba(51, 65, 85, 0.5)' }
            },
          },
        },
      });
    }

    return () => {
      if (rateChartRef.current) {
        rateChartRef.current.destroy();
        rateChartRef.current = null;
      }
    };
  }, [graph.labels, rateSeries]);

  return (
    <div className="dashboard-page">
      {error && <div className="alert alert-danger">{error}</div>}
      {loading && !metrics ? (
        <div className="text-muted">Loading dashboard...</div>
      ) : (
        <>
          <DashboardMetrics metrics={metrics} />

          <div className="row g-3 mt-1">
            <div className="col-12 col-lg-6" style={{ minHeight: 320 }}>
              <div className="card card-outline card-danger h-100">
                <div className="card-header border-0">
                  <h3 className="card-title mb-0">Malicious Rate (%)</h3>
                </div>
                <div className="card-body">
                  <div style={{ height: 260 }}>
                    <canvas ref={rateCanvasRef} />
                  </div>
                </div>
              </div>
            </div>
            <div className="col-12 col-lg-6" style={{ minHeight: 320 }}>
              <div className="card card-outline card-info h-100">
                <div className="card-header border-0">
                  <h3 className="card-title mb-0">Total Volume</h3>
                </div>
                <div className="card-body">
                  <div style={{ height: 260 }}>
                    <canvas ref={totalCanvasRef} />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="card card-outline card-secondary mt-3">
            <div className="card-header border-0 d-flex justify-content-between align-items-center">
              <h3 className="card-title mb-0">Recent Email Activity</h3>
              <div className="d-flex align-items-center gap-2">
                <div className="form-check form-switch">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id="autoRefreshToggle"
                    checked={autoRefreshEnabled}
                    onChange={(e) => {
                      const v = !!e.target.checked;
                      setAutoRefreshEnabled(v);
                      try {
                        localStorage.setItem('dashboard:autorefresh', JSON.stringify(v));
                      } catch (err) {}
                    }}
                  />
                  <label className="form-check-label small text-muted" htmlFor="autoRefreshToggle">
                    Auto-refresh
                  </label>
                </div>

                {/* small spinner that appears briefly when auto-refresh runs */}
                {refreshing && (
                  <div title="Auto-refresh running" className="ms-2">
                    <span className="spinner-border spinner-border-sm text-primary" role="status" aria-hidden="true" />
                  </div>
                )}

                <input
                  type="number"
                  min={5}
                  className="form-control form-control-sm"
                  style={{ width: 90 }}
                  value={autoRefreshIntervalInput}
                  onChange={(e) => {
                    setAutoRefreshIntervalInput(e.target.value);
                  }}
                  placeholder="Seconds"
                />

                <Link className="btn btn-sm btn-outline-primary" to="/emails">
                  View all
                </Link>
              </div>
            </div>
            <div className="card-body p-0">
              <RecentTable items={recent} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}