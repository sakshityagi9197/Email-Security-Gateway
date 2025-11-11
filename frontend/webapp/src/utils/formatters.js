export function statusTone(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'BLOCK' || s === 'BLOCKED') return 'bad';
  if (s === 'QUARANTINE' || s === 'QUARANTINED') return 'warn';
  return 'ok';
}

export function statusLabel(status) {
  const s = String(status || '').toUpperCase();
  if (s === 'BLOCK' || s === 'BLOCKED') return 'Blocked';
  if (s === 'QUARANTINE' || s === 'QUARANTINED') return 'Quarantined';
  if (s === 'FORWARD' || s === 'FORWARDED') return 'Forwarded';
  return status || '';
}

export function formatNumber(value) {
  const num = Number(value ?? 0);
  if (!Number.isFinite(num)) return '0';
  if (Math.abs(num) >= 1000) {
    return Math.round(num).toLocaleString();
  }
  return num.toString();
}

export function formatBytes(bytes) {
  const value = Number(bytes ?? 0);
  if (!Number.isFinite(value) || value <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = size < 10 && unitIndex > 0 ? 1 : 0;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

export function parseSender(sender) {
  if (!sender) {
    return { name: '', email: '' };
  }
  const text = String(sender);
  const match = text.match(/^\s*"?([^"<]*)"?\s*(?:<([^>]+)>)?\s*$/);
  if (match) {
    let name = (match[1] || '').trim();
    let email = (match[2] || '').trim();
    if (!name && email) {
      name = email.split('@')[0];
    }
    return { name, email };
  }
  return { name: text.trim(), email: '' };
}