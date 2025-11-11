import { statusLabel, statusTone } from '../utils/formatters.js';

export default function StatusBadge({ status, children }) {
  const tone = statusTone(status);
  const text = children ?? statusLabel(status);
  return <span className={`status-badge ${tone}`}>{text}</span>;
}