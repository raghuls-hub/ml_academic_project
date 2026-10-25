import React, { useState } from 'react';

/**
 * Executive-Grade Flow Analytics Chart
 * Plots Packet Duration (s) vs Bytes Transferred (KB)
 * Supports Recharts or High-Precision SVG Rendering with tooltips & cyber glows.
 */
export function FlowAnalyticsChart({ data = [], height = 240 }) {
  const [hoveredPoint, setHoveredPoint] = useState(null);

  if (!data || data.length === 0) {
    return (
      <div className="h-60 flex items-center justify-center text-xs font-mono text-slate-500">
        No flow data available
      </div>
    );
  }

  // Find max values for scaling
  const maxDuration = Math.max(...data.map(d => d.duration || 1), 15);
  const maxBytes = Math.max(...data.map(d => d.bytes || 100), 20000);

  const width = 600;
  const padding = { top: 20, right: 30, bottom: 40, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  return (
    <div className="relative w-full overflow-hidden">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto overflow-visible select-none"
      >
        <defs>
          <linearGradient id="cyberAreaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
          </linearGradient>
          <filter id="glowEffect" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
          const y = padding.top + chartHeight * (1 - pct);
          return (
            <g key={idx}>
              <line
                x1={padding.left}
                y1={y}
                x2={width - padding.right}
                y2={y}
                stroke="#1e293b"
                strokeDasharray="4 4"
                strokeWidth="1"
              />
              <text
                x={padding.left - 8}
                y={y + 4}
                textAnchor="end"
                className="text-[10px] font-mono fill-slate-500"
              >
                {Math.round((maxBytes * pct) / 1000)}k
              </text>
            </g>
          );
        })}

        {/* X Axis Ticks */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
          const x = padding.left + chartWidth * pct;
          return (
            <g key={idx}>
              <line
                x1={x}
                y1={height - padding.bottom}
                x2={x}
                y2={height - padding.bottom + 5}
                stroke="#334155"
                strokeWidth="1"
              />
              <text
                x={x}
                y={height - padding.bottom + 18}
                textAnchor="middle"
                className="text-[10px] font-mono fill-slate-500"
              >
                {Math.round(maxDuration * pct)}s
              </text>
            </g>
          );
        })}

        {/* Axis Labels */}
        <text
          x={padding.left - 42}
          y={padding.top + chartHeight / 2}
          textAnchor="middle"
          transform={`rotate(-90, ${padding.left - 42}, ${padding.top + chartHeight / 2})`}
          className="text-[10px] font-mono fill-slate-400 font-semibold"
        >
          TRANSFER (BYTES)
        </text>
        <text
          x={padding.left + chartWidth / 2}
          y={height - 8}
          textAnchor="middle"
          className="text-[10px] font-mono fill-slate-400 font-semibold"
        >
          FLOW DURATION (SECONDS)
        </text>

        {/* Area / Path Curve */}
        {data.length > 1 && (
          <path
            d={
              data
                .map((d, i) => {
                  const x = padding.left + (d.duration / maxDuration) * chartWidth;
                  const y = padding.top + chartHeight * (1 - (d.bytes / maxBytes));
                  return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
                })
                .join(' ') +
              ` L ${padding.left + (data[data.length - 1].duration / maxDuration) * chartWidth} ${padding.top + chartHeight} L ${padding.left} ${padding.top + chartHeight} Z`
            }
            fill="url(#cyberAreaGrad)"
          />
        )}

        {/* Connecting Line */}
        {data.length > 1 && (
          <path
            d={data
              .map((d, i) => {
                const x = padding.left + (d.duration / maxDuration) * chartWidth;
                const y = padding.top + chartHeight * (1 - (d.bytes / maxBytes));
                return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
              })
              .join(' ')}
            fill="none"
            stroke="#06b6d4"
            strokeWidth="2"
            filter="url(#glowEffect)"
          />
        )}

        {/* Data Points */}
        {data.map((d, i) => {
          const x = padding.left + (d.duration / maxDuration) * chartWidth;
          const y = padding.top + chartHeight * (1 - (d.bytes / maxBytes));
          const isCritical = d.threatLevel === 'CRITICAL';
          const isHigh = d.threatLevel === 'HIGH';
          const pointColor = isCritical ? '#f43f5e' : isHigh ? '#f59e0b' : '#22d3ee';

          return (
            <g
              key={i}
              className="cursor-pointer transition-transform"
              onMouseEnter={() => setHoveredPoint({ ...d, x, y })}
              onMouseLeave={() => setHoveredPoint(null)}
            >
              <circle
                cx={x}
                cy={y}
                r={isCritical ? 7 : 5}
                fill={pointColor}
                stroke="#090d16"
                strokeWidth="2"
                className="transition-all hover:r-8"
              />
              {isCritical && (
                <circle
                  cx={x}
                  cy={y}
                  r="12"
                  fill="none"
                  stroke="#f43f5e"
                  strokeWidth="1.5"
                  className="animate-ping opacity-60"
                />
              )}
            </g>
          );
        })}
      </svg>

      {/* Floating Tooltip */}
      {hoveredPoint && (
        <div
          className="absolute z-30 pointer-events-none p-2.5 rounded-lg bg-[#0b1322] border border-cyan-500/50 shadow-xl shadow-cyan-950/80 text-[11px] font-mono text-slate-200"
          style={{
            left: `${Math.min(Math.max((hoveredPoint.x / width) * 100, 10), 80)}%`,
            top: `${Math.max((hoveredPoint.y / height) * 100 - 35, 5)}%`,
            transform: 'translate(-50%, -100%)',
          }}
        >
          <div className="flex items-center justify-between gap-3 font-bold mb-1">
            <span className="text-white">{hoveredPoint.service || 'Flow Trace'}</span>
            <span
              className={`px-1.5 py-0.2 rounded text-[9px] ${
                hoveredPoint.threatLevel === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border border-rose-700'
                  : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              }`}
            >
              {hoveredPoint.threatLevel || 'NORMAL'}
            </span>
          </div>
          <div className="text-slate-400">Duration: <span className="text-white font-semibold">{hoveredPoint.duration}s</span></div>
          <div className="text-slate-400">Transferred: <span className="text-cyan-300 font-semibold">{hoveredPoint.bytes?.toLocaleString()} B</span></div>
          <div className="text-slate-400">Flag: <span className="text-amber-400 font-semibold">{hoveredPoint.flag}</span></div>
        </div>
      )}
    </div>
  );
}

/**
 * 24-Hour User Access Risk Matrix Chart
 * Visualizes normal business hour baselines vs off-hours outlier spikes
 */
export function UserAccessMatrixChart({ hourlyData = [], height = 220 }) {
  const maxCount = Math.max(...hourlyData.map(d => d.totalAccesses || 1), 50);
  const width = 600;
  const padding = { top: 20, right: 25, bottom: 35, left: 45 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const barWidth = chartWidth / 24;

  return (
    <div className="w-full overflow-hidden">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto select-none">
        {/* Off-hours background highlights (0-6 hrs and 20-23 hrs) */}
        <rect
          x={padding.left}
          y={padding.top}
          width={barWidth * 6}
          height={chartHeight}
          fill="rgba(244, 63, 94, 0.06)"
        />
        <rect
          x={padding.left + barWidth * 20}
          y={padding.top}
          width={barWidth * 4}
          height={chartHeight}
          fill="rgba(244, 63, 94, 0.06)"
        />
        {/* Core business hours background (8-18 hrs) */}
        <rect
          x={padding.left + barWidth * 8}
          y={padding.top}
          width={barWidth * 10}
          height={chartHeight}
          fill="rgba(16, 185, 129, 0.04)"
        />

        {/* Grid lines */}
        {[0, 0.5, 1].map((pct, idx) => {
          const y = padding.top + chartHeight * (1 - pct);
          return (
            <line
              key={idx}
              x1={padding.left}
              y1={y}
              x2={width - padding.right}
              y2={y}
              stroke="#1e293b"
              strokeDasharray="4 4"
            />
          );
        })}

        {/* Bars */}
        {hourlyData.map((d, hr) => {
          const barH = (d.totalAccesses / maxCount) * chartHeight;
          const x = padding.left + hr * barWidth + 2;
          const y = padding.top + chartHeight - barH;
          const isAnomalous = d.isOutlier || (hr < 6 && d.totalAccesses > 5);

          return (
            <g key={hr}>
              <rect
                x={x}
                y={y}
                width={Math.max(barWidth - 4, 3)}
                height={Math.max(barH, 2)}
                rx="2"
                fill={isAnomalous ? '#f43f5e' : hr >= 8 && hr <= 18 ? '#06b6d4' : '#64748b'}
                className="transition-all hover:opacity-80"
              />
              {isAnomalous && (
                <circle
                  cx={x + (barWidth - 4) / 2}
                  cy={y - 5}
                  r="2.5"
                  fill="#fb7185"
                />
              )}
            </g>
          );
        })}

        {/* Hour markers */}
        {[0, 4, 8, 12, 16, 20, 23].map((hr) => {
          const x = padding.left + hr * barWidth + barWidth / 2;
          return (
            <text
              key={hr}
              x={x}
              y={height - 12}
              textAnchor="middle"
              className="text-[10px] font-mono fill-slate-500"
            >
              {String(hr).padStart(2, '0')}:00
            </text>
          );
        })}

        {/* Labels */}
        <text
          x={padding.left + barWidth * 3}
          y={padding.top + 14}
          textAnchor="middle"
          className="text-[9px] font-mono fill-rose-400 font-bold"
        >
          HIGH RISK OFF-HOURS
        </text>
        <text
          x={padding.left + barWidth * 13}
          y={padding.top + 14}
          textAnchor="middle"
          className="text-[9px] font-mono fill-emerald-400 font-bold"
        >
          AUTHORIZED SHIFT
        </text>
      </svg>
    </div>
  );
}

/**
 * Syscall Execution Rate Sparkline / Bar Graph
 */
export function SyscallDistributionBar({ events = [] }) {
  const total = events.reduce((acc, curr) => acc + curr.count, 0) || 1;

  return (
    <div className="space-y-3 font-mono">
      <div className="w-full h-3 rounded-full bg-slate-900 overflow-hidden flex">
        {events.map((ev, idx) => {
          const widthPct = (ev.count / total) * 100;
          return (
            <div
              key={idx}
              className={`${ev.color || 'bg-cyan-500'} h-full transition-all`}
              style={{ width: `${widthPct}%` }}
              title={`${ev.name}: ${ev.count} (${widthPct.toFixed(1)}%)`}
            />
          );
        })}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        {events.map((ev, idx) => (
          <div key={idx} className="flex items-center space-x-2">
            <span className={`w-2.5 h-2.5 rounded-sm ${ev.color || 'bg-cyan-500'}`} />
            <span className="text-slate-400 text-[11px] truncate">{ev.name}</span>
            <span className="text-white text-[11px] font-bold ml-auto">{ev.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

