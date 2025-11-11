import { useMemo } from 'react';
import { validatePasswordStrength } from '../utils/helpers.js';

/**
 * Password strength meter component
 */
export default function PasswordStrengthMeter({ password }) {
  const result = useMemo(() => validatePasswordStrength(password), [password]);

  if (!password) return null;

  const getColorClass = () => {
    switch (result.strength) {
      case 'weak':
        return 'bg-danger';
      case 'medium':
        return 'bg-warning';
      case 'strong':
        return 'bg-success';
      case 'very-strong':
        return 'bg-primary';
      default:
        return 'bg-secondary';
    }
  };

  const getWidthPercent = () => {
    switch (result.strength) {
      case 'weak':
        return 25;
      case 'medium':
        return 50;
      case 'strong':
        return 75;
      case 'very-strong':
        return 100;
      default:
        return 0;
    }
  };

  return (
    <div className="mt-2">
      <div className="progress" style={{ height: '6px' }}>
        <div
          className={`progress-bar ${getColorClass()}`}
          role="progressbar"
          style={{ width: `${getWidthPercent()}%` }}
          aria-valuenow={getWidthPercent()}
          aria-valuemin="0"
          aria-valuemax="100"
        />
      </div>
      <small className={`form-text ${result.valid ? 'text-success' : 'text-danger'}`}>
        {result.message}
      </small>
    </div>
  );
}
