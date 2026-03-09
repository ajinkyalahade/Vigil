import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiHealth, apiMetricsOverview } from "../api/client";
import { IconActivity, IconAlert } from "../components/Icons";
import type { MetricsOverview } from "../types";

// ── Arrow icon ─────────────────────────────────────────
function ArrowIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
      <path d="M7 17L17 7M17 7H7M17 7v10" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ChevronIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
      <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Bar chart (scan activity mock) ─────────────────────
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

const BAR_DATA = [
  { plan: 62, fact: 48 },
  { plan: 80, fact: 72 },
  { plan: 75, fact: 65 },
  { plan: 92, fact: 88 },
  { plan: 85, fact: 74 },
  { plan: 58, fact: 53 },
  { plan: 50, fact: 42 },
];

// ── March 2026 calendar ────────────────────────────────
// March 1 = Sunday → Mon-start offset = 6
const CAL_OFFSET = 6;
const CAL_DAYS   = 31;
// Scan activity days (mock — would come from real data)
const SCAN_DAYS = new Set([3, 5, 8, 12, 15, 19, 22, 26, 29]);

export default function Overview() {
  const [health,   setHealth]   = useState<string>("loading…");
  const [overview, setOverview] = useState<MetricsOverview | null>(null);
  const [error,    setError]    = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [h, o] = await Promise.all([apiHealth(), apiMetricsOverview()]);
        if (cancelled) return;
        setHealth(h.status);
        setOverview(o);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const latest       = overview?.latest_run ?? null;
  const sev          = overview?.latest_counts_by_severity ?? {};
  const cat          = overview?.latest_counts_by_category ?? {};
  const highCritical = (sev.high ?? 0) + (sev.critical ?? 0);
  const totalFindings = Object.values(sev).reduce((a, b) => a + b, 0);

  const apiOk = health === "ok";

  // Security grade
  const grade =
    !apiOk || totalFindings === 0 ? "—"
    : highCritical === 0          ? "A"
    : highCritical < 5            ? "B"
    : highCritical < 15           ? "C"
    : "D";

  const gradeColor =
    grade === "A" ? "var(--good)"
    : grade === "B" ? "var(--gold)"
    : grade === "C" ? "var(--warn)"
    : grade === "D" ? "var(--bad)"
    : "var(--text-2)";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>

      {/* ── KPI Cards ─────────────────────────────────────── */}
      <div className="kpiGrid">

        {/* 1 — Total Scans (gold) */}
        <div className="kpiCard gold">
          <div className="kpiCardTop">
            <div className="kpiCardTitle">Total Scans</div>
            <button className="kpiArrowBtn"><ArrowIcon /></button>
          </div>
          <div className="kpiCardValueRow">
            <span className="kpiCardValue">
              {overview ? (latest ? "1" : "0") : "—"}
            </span>
            <span className="kpiCardUnit">runs</span>
          </div>
        </div>

        {/* 2 — High / Critical */}
        <div className="kpiCard default">
          <div className="kpiCardTop">
            <div className="kpiCardTitle">High / Critical</div>
            <button className="kpiArrowBtn"><ArrowIcon /></button>
          </div>
          <div className="kpiCardValueRow">
            <span className="kpiCardValue" style={{ color: highCritical > 0 ? "var(--bad)" : undefined }}>
              {highCritical}
            </span>
            <span className="kpiCardUnit">findings</span>
          </div>
        </div>

        {/* 3 — Total Findings */}
        <div className="kpiCard default">
          <div className="kpiCardTop">
            <div className="kpiCardTitle">Total Findings</div>
            <button className="kpiArrowBtn"><ArrowIcon /></button>
          </div>
          <div className="kpiCardValueRow">
            <span className="kpiCardValue">{totalFindings}</span>
            <span className="kpiCardUnit">total</span>
          </div>
        </div>

        {/* 4 — Security Grade */}
        <div className="kpiCard default">
          <div className="kpiCardTop">
            <div className="kpiCardTitle">Security Grade</div>
            <button className="kpiArrowBtn"><ArrowIcon /></button>
          </div>
          <div className="kpiCardValueRow">
            <span className="kpiCardValue" style={{ color: gradeColor }}>{grade}</span>
            <span className="kpiCardUnit">score</span>
          </div>
        </div>
      </div>

      {/* ── Status banner ─────────────────────────────────── */}
      {error && (
        <div className="callout error" style={{ marginBottom: 14 }}>
          <div className="calloutLeft">
            <div className="calloutIcon"><IconAlert size={16} /></div>
            <div>
              <div className="calloutTitle">Connection Error</div>
              <div className="calloutText">{error}</div>
            </div>
          </div>
        </div>
      )}

      {!apiOk && !error && (
        <div className="callout" style={{ marginBottom: 14 }}>
          <div className="calloutLeft">
            <div className="calloutIcon"><IconActivity size={16} /></div>
            <div>
              <div className="calloutTitle">Backend is offline</div>
              <div className="calloutText">Start the API server to see live security data.</div>
            </div>
          </div>
          <Link className="btn" to="/scans">Run a Scan</Link>
        </div>
      )}

      {/* ── Charts row ────────────────────────────────────── */}
      <div className="dashGrid" style={{ marginBottom: 14 }}>

        {/* Bar chart */}
        <div className="panel">
          <div className="panelHeader">
            <div className="panelTitle">Scan Activity</div>
            <div className="periodBadge">Week <ChevronIcon /></div>
          </div>
          <div className="barChart">
            <div className="barChartBars">
              {BAR_DATA.map((d, i) => (
                <div key={i} className="barGroup" style={{ maxWidth: 48, height: "100%" }}>
                  <div
                    className="bar plan"
                    style={{ height: `${(d.plan / 100) * 140}px` }}
                  />
                  <div
                    className="bar fact"
                    style={{ height: `${(d.fact / 100) * 140}px` }}
                  />
                </div>
              ))}
            </div>
            <div className="barChartAxisLine" />
            <div className="barChartLabels">
              {DAYS.map(d => <span key={d}>{d}</span>)}
            </div>
            <div className="barChartLegend">
              <div className="legendItem">
                <div
                  className="legendSwatch"
                  style={{
                    background: "repeating-linear-gradient(45deg,rgba(124,124,247,0.35),rgba(124,124,247,0.35) 2px,transparent 2px,transparent 5px)",
                    border: "1.5px solid rgba(124,124,247,0.35)",
                  }}
                />
                Plan
              </div>
              <div className="legendItem">
                <div className="legendSwatch" style={{ background: "var(--accent)" }} />
                Fact
              </div>
            </div>
          </div>
        </div>

        {/* Calendar */}
        <div className="panel">
          <div className="panelHeader">
            <div className="panelTitle">Activity in March</div>
            <div className="periodBadge">Month <ChevronIcon /></div>
          </div>
          <div className="calGrid">
            {/* Day headers */}
            {["Mon","Tue","Wed","Thu","Fri","Sat","Sun"].map(d => (
              <div key={d} className="calDayLabel">{d}</div>
            ))}
            {/* Empty offset cells */}
            {Array.from({ length: CAL_OFFSET }, (_, i) => (
              <div key={`e${i}`} className="calDay empty" />
            ))}
            {/* Day cells */}
            {Array.from({ length: CAL_DAYS }, (_, i) => {
              const day = i + 1;
              const isToday = day === 8; // March 8 = today
              const hasScan = SCAN_DAYS.has(day);
              const cls = [
                "calDay",
                isToday ? "today" : "",
                hasScan && !isToday ? "scan" : "",
              ].filter(Boolean).join(" ");
              return (
                <div key={day} className={cls}>{day}</div>
              );
            })}
          </div>
          <div className="calLegend">
            <div className="calLegendItem">
              <div className="calLegendDot" style={{ background: "var(--panel-2)", border: "1px solid var(--border-2)" }} />
              No activity
            </div>
            <div className="calLegendItem">
              <div className="calLegendDot" style={{ background: "rgba(124,124,247,0.25)", border: "1px solid rgba(124,124,247,0.35)" }} />
              Scan run
            </div>
            <div className="calLegendItem">
              <div className="calLegendDot" style={{ background: "transparent", border: "1px solid var(--gold)" }} />
              Today
            </div>
          </div>
        </div>
      </div>

      {/* ── Severity + Latest Run ──────────────────────────── */}
      <div className="dashGrid">

        {/* Severity breakdown */}
        <div className="panel">
          <div className="panelHeader">
            <div className="panelTitle">Severity Breakdown</div>
          </div>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Share</th>
              </tr>
            </thead>
            <tbody>
              {(["critical","high","medium","low","info"] as const).map(s => {
                const count = sev[s] ?? 0;
                const pct   = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
                const barColor =
                  s === "critical" ? "var(--crit)"
                  : s === "high"   ? "var(--bad)"
                  : s === "medium" ? "var(--warn)"
                  : s === "low"    ? "var(--good)"
                  : "var(--muted)";
                return (
                  <tr key={s}>
                    <td><span className={`badge ${s}`}>{s}</span></td>
                    <td style={{ fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", fontSize: 15 }}>{count}</td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <div className="miniBar">
                          <div className="miniBarFill" style={{ width: `${pct}%`, background: barColor }} />
                        </div>
                        <span style={{ fontSize: 12, color: "var(--muted)", minWidth: 28 }}>{pct}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Latest run + category hotspots */}
        <div className="panel">
          <div className="panelHeader">
            <div className="panelTitle">Latest Run</div>
            <Link className="btn secondary" to="/scans" style={{ fontSize: 12, padding: "5px 14px" }}>
              See all
            </Link>
          </div>

          {latest ? (
            <table>
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="mono">
                    <Link to={`/runs/${latest.id}`} style={{ color: "var(--accent)" }}>
                      #{latest.id}
                    </Link>
                  </td>
                  <td>
                    <span className={`badge ${latest.status === "completed" ? "completed" : latest.status === "running" ? "running" : "info"}`}>
                      {latest.status}
                    </span>
                  </td>
                  <td style={{ color: "var(--text-2)", fontSize: 13 }}>{latest.created_at}</td>
                </tr>
              </tbody>
            </table>
          ) : (
            <div style={{ padding: "16px 0 8px", display: "flex", flexDirection: "column", gap: 14 }}>
              <div style={{ color: "var(--text-2)", fontSize: 14 }}>
                No runs yet. Start your first scan.
              </div>
              <Link className="btn" to="/scans" style={{ width: "fit-content" }}>
                Go to Scans
              </Link>
            </div>
          )}

          {/* Category hotspots */}
          {Object.keys(cat).length > 0 && (
            <>
              <div style={{ borderTop: "1px solid var(--border)", margin: "18px 0 14px" }} />
              <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 10 }}>Category Hotspots</div>
              <div className="pillRow" style={{ marginTop: 0 }}>
                {Object.entries(cat)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 6)
                  .map(([k, v]) => (
                    <span key={k} className="pill">
                      <span className="pillDot" />
                      {k}: {v}
                    </span>
                  ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
