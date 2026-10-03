import * as React from 'react';
import { Badge } from './Badge';
import { normalizeRisk, getRiskConfig } from '../../utils/risk';
import { ShieldCheck, AlertTriangle, AlertOctagon, Info, ShieldAlert } from 'lucide-react';
import { cn } from '../../utils/cn';

const RISK_ICONS = {
  safe: ShieldCheck,
  low: Info,
  medium: AlertTriangle,
  high: AlertOctagon,
  critical: ShieldAlert,
};

/**
 * Specialized CYBERGUARD Risk Badge
 * Custom wrapper around shadcn/ui Badge.
 * Normalizes ANY string input via utils/risk.js.
 * Calibrated for optimal contrast across both Light and Dark themes.
 *
 * @param {{
 *   level?: string,
 *   score?: number | string,
 *   size?: 'sm' | 'md' | 'lg',
 *   showDot?: boolean,
 *   showIcon?: boolean,
 *   className?: string
 * }} props
 */
export function RiskBadge({
  level = 'low',
  score,
  size = 'md',
  showDot = true,
  showIcon = false,
  className,
  ...props
}) {
  const normalizedKey = normalizeRisk(level);
  const config = getRiskConfig(normalizedKey);
  const IconComponent = RISK_ICONS[config.key] || Info;

  return (
    <Badge
      variant="outline"
      size={size}
      className={cn(
        'font-mono uppercase tracking-wider font-semibold transition-all select-none gap-1.5',
        config.badgeClass,
        className
      )}
      title={config.description}
      {...props}
    >
      {showDot && (
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full shrink-0',
            config.dotClass
          )}
        />
      )}

      {showIcon && <IconComponent className="w-3.5 h-3.5 shrink-0" />}

      <span>{config.label}</span>

      {score !== undefined && score !== null && (
        <span className="opacity-75 font-normal pl-1 border-l border-current/25 text-[10px]">
          {score}
        </span>
      )}
    </Badge>
  );
}
