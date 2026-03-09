import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiListRuns } from "../api/client";
import type { RunSummary } from "../types";

export default function Findings() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await apiListRuns(30);
        if (cancelled) return;
        setRuns(r);
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="grid">
      <div className="topbar">
        <div>
          <h1 className="h1">Findings</h1>
          <div className="subtitle">Open a run to view findings, diffs, and artifacts.</div>
        </div>
        <Link className="btn" to="/scans">
          Run a Scan
        </Link>
      </div>

      {error ? <div className="card">Error: {error}</div> : null}

      <div className="card">
        <div className="cardTitle">Pick a run</div>
        <div className="muted" style={{ marginTop: 8 }}>
          Findings are attached to scan runs. Open a run to view its findings.
        </div>
        <div style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link to={`/runs/${r.id}`}>{r.id}</Link>
                  </td>
                  <td>
                    <span className="badge info">{r.status}</span>
                  </td>
                  <td className="muted">{r.created_at}</td>
                </tr>
              ))}
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={3} className="muted">
                    No runs yet.
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
