import { useEffect, useMemo, useState } from "react";
import { apiMetricsTrends } from "../api/client";
import LineChart from "../components/LineChart";
import type { MetricsTrends, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function Analytics() {
  const [data, setData] = useState<MetricsTrends | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState<number>(30);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const d = await apiMetricsTrends(days);
        if (cancelled) return;
        setData(d);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [days]);

  const byDay = useMemo(() => {
    const map = new Map<string, Record<string, number>>();
    for (const p of data?.points ?? []) {
      const row = map.get(p.date) ?? {};
      row[p.severity] = (row[p.severity] ?? 0) + p.count;
      map.set(p.date, row);
    }
    return Array.from(map.entries())
      .map(([date, counts]) => ({ date, counts }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [data]);

  const highCriticalSeries = useMemo(() => {
    return byDay.map((d) => (d.counts.high ?? 0) + (d.counts.critical ?? 0));
  }, [byDay]);

  const labels = useMemo(() => {
    if (!byDay.length) return [];
    const step = Math.max(1, Math.ceil(byDay.length / 6));
    return byDay.map((d, i) => (i % step === 0 || i === byDay.length - 1 ? d.date.slice(5) : ""));
  }, [byDay]);

  return (
    <div className="grid">
      <div className="topbar">
        <div>
          <h1 className="h1">Analytics</h1>
          <div className="subtitle">Trends across scan runs over time.</div>
        </div>
        <div className="row">
          <span className="pill">
            <span className="pillDot" />
            Range: {days} days
          </span>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7</option>
            <option value={30}>30</option>
            <option value={90}>90</option>
          </select>
        </div>
      </div>

      {error ? <div className="card">Error: {error}</div> : null}

      <div className="card">
        <div className="cardTitle">High/Critical Trend</div>
        <div className="muted" style={{ marginTop: 8 }}>
          Counts are aggregated by scan run date (UTC). This is a best-effort rollup.
        </div>
        <div style={{ marginTop: 12 }}>
          {byDay.length ? (
            <LineChart values={highCriticalSeries} labels={labels} />
          ) : (
            <div className="muted">No trend data yet.</div>
          )}
        </div>
        <div style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Date</th>
                {SEVERITIES.map((s) => (
                  <th key={s}>{s}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {byDay.map((d) => (
                <tr key={d.date}>
                  <td className="muted">{d.date}</td>
                  {SEVERITIES.map((s) => (
                    <td key={s}>{d.counts[s] ?? 0}</td>
                  ))}
                </tr>
              ))}
              {byDay.length === 0 ? (
                <tr>
                  <td className="muted" colSpan={1 + SEVERITIES.length}>
                    No trend data yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
