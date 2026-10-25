import React from 'react';
import { AlertCircle, CheckCircle, TrendingUp, ShieldAlert, Info } from 'lucide-react';

export default function MetricCard({
  title,
  value,
  subtitle,
  score,          // Numeric value 0.0 to 1.0 (optional)
  threshold = 0.65,
  unit = '',
  status = 'normal', // 'normal' | 'warning' | 'critical'
  icon: Icon,
  badge,
}) {
  // Determine severity color themes
  const isCritical = status === 'critical' || (typeof score === 'number' && score >= 0.75);
  const isWarning = status === 'warning' || (typeof score === 'number' && score >= threshold && score < 0.75);

  const getCardTheme = () => {
    if (isCritical) {
      return {
        border: 'border-rose-500/50 bg-gradient-to-b from-rose-950/20 to-slate-900/90',
        text: 'text-rose-400',
        bar: 'bg-rose-500 shadow-rose-500/50',
        badgeBg: 'bg-rose-950 text-rose-400 border-rose-800',
        glow: 'shadow-lg shadow-rose-950/30'
      };
    }
    if (isWarning) {
      return {
        border: 'border-amber-500/40 bg-gradient-to-b from-amber-950/20 to-slate-900/90',
        text: 'text-amber-400',
        bar: 'bg-amber-500 shadow-amber-500/50',
        badgeBg: 'bg-amber-950 text-amber-400 border-amber-800',
        glow: 'shadow-lg shadow-amber-950/30'
      };
    }
    return {
      border: 'border-slate-800 bg-[#0f172a]/80 hover:border-slate-700',
      text: 'text-cyan-400',
      bar: 'bg-cyan-500 shadow-cyan-500/50',
      badgeBg: 'bg-slate-800 text-slate-300 border-slate-700',
      glow: ''
    };
  };

  const theme = getCardTheme();

  return (
    <div className={`p-5 rounded-xl border backdrop-blur transition-all duration-200 ${theme.border} ${theme.glow}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          {Icon && <Icon className="w-4 h-4 text-slate-400" />}
          {title}
        </span>
        {badge && (
          <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${theme.badgeBg}`}>
            {badge}
          </span>
        )}
      </div>

      <div className="flex items-baseline space-x-2 my-1">
        <span className={`text-2xl font-bold font-mono tracking-tight ${theme.text}`}>
          {value}
        </span>
        {unit && <span className="text-xs text-slate-400">{unit}</span>}
      </div>

      {typeof score === 'number' && (
        <div className="mt-3">
          <div className="flex justify-between text-[11px] font-mono text-slate-400 mb-1">
            <span>Threat Index</span>
            <span className={theme.text}>{(score * 100).toFixed(1)}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${theme.bar}`}
              style={{ width: `${Math.min(Math.max(score * 100, 0), 100)}%` }}
            />
          </div>
        </div>
      )}

      {subtitle && (
        <p className="text-xs text-slate-400 mt-2.5 flex items-center gap-1.5">
          <Info className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span>{subtitle}</span>
        </p>
      )}
    </div>
  );
}

