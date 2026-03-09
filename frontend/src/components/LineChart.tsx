import type { CSSProperties } from "react";

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export default function LineChart({
  values,
  labels,
  height = 220,
}: {
  values: number[];
  labels?: string[];
  height?: number;
}) {
  const width = 900;
  const h = Math.max(120, height);
  const padX = 18;
  const padY = 18;

  const safe = values.length ? values : [0];
  const maxV = Math.max(...safe, 1);

  const pts = safe
    .map((v, i) => {
      const x =
        safe.length === 1
          ? width / 2
          : padX + (i / (safe.length - 1)) * (width - padX * 2);
      const y = padY + (1 - v / maxV) * (h - padY * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  const area = `${padX},${h - padY} ${pts} ${width - padX},${h - padY}`;

  const style: CSSProperties = {
    overflow: "hidden",
    borderRadius: "12px",
    border: "1px solid rgba(15, 23, 42, 0.08)",
    background: "linear-gradient(180deg, rgba(37, 99, 235, 0.06), rgba(255,255,255,0))",
  };

  return (
    <div className="chart" style={style}>
      <svg viewBox={`0 0 ${width} ${h}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="scArea" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="rgba(37, 99, 235, 0.25)" />
            <stop offset="100%" stopColor="rgba(37, 99, 235, 0.02)" />
          </linearGradient>
        </defs>

        {/* grid */}
        {[0.25, 0.5, 0.75].map((t) => {
          const y = padY + t * (h - padY * 2);
          return (
            <line
              key={t}
              x1={padX}
              x2={width - padX}
              y1={y}
              y2={y}
              stroke="rgba(15, 23, 42, 0.08)"
              strokeWidth="1"
            />
          );
        })}

        <polyline points={area} fill="url(#scArea)" stroke="none" />
        <polyline
          points={pts}
          fill="none"
          stroke="rgba(37, 99, 235, 0.95)"
          strokeWidth="3"
          strokeLinejoin="round"
          strokeLinecap="round"
        />

        {safe.map((v, i) => {
          const x =
            safe.length === 1
              ? width / 2
              : padX + (i / (safe.length - 1)) * (width - padX * 2);
          const y = padY + (1 - v / maxV) * (h - padY * 2);
          const label = labels?.[i];
          return (
            <g key={i}>
              <circle cx={x} cy={y} r="4.5" fill="#fff" stroke="rgba(37, 99, 235, 0.95)" strokeWidth="2" />
              {label ? (
                <text
                  x={x}
                  y={h - 6}
                  textAnchor="middle"
                  fontSize="11"
                  fill="rgba(100, 116, 139, 0.95)"
                >
                  {label}
                </text>
              ) : null}
            </g>
          );
        })}

        <text x={padX} y={14} fontSize="12" fill="rgba(100, 116, 139, 0.95)">
          0
        </text>
        <text x={padX} y={clamp(padY + 12, 12, h - 6)} fontSize="12" fill="rgba(100, 116, 139, 0.95)">
          {maxV}
        </text>
      </svg>
    </div>
  );
}

