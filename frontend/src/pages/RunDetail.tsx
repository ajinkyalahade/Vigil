import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { apiGetRun, apiGetRunDiff } from "../api/client";
import FindingResolution from "../components/FindingResolution";
import SeverityBadge from "../components/SeverityBadge";
import type { Finding, RunDetail, RunDiff } from "../types";

function matchesQuery(f: Finding, q: string): boolean {
  if (!q) return true;
  const hay = `${f.severity} ${f.category} ${f.title} ${f.description} ${f.scanner_id}`.toLowerCase();
  return hay.includes(q.toLowerCase());
}

export default function RunDetailPage() {
  const { runId } = useParams();
  const [data, setData] = useState<RunDetail | null>(null);
  const [diff, setDiff] = useState<RunDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState<string>("");

  function exportFindingsJson() {
    if (!data) return;
    const payload = {
      run: data.run,
      findings: data.findings,
      artifacts: data.artifacts,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-check-${data.run.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let timer: number | undefined;

    const load = async () => {
      try {
        const d = await apiGetRun(runId);
        if (cancelled) return;
        setData(d);
        setError(null);
        if (d.run.status === "queued" || d.run.status === "running") {
          timer = window.setTimeout(load, 1500);
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    };

    load();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [runId]);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    (async () => {
      try {
        const d = await apiGetRunDiff(runId, "previous");
        if (cancelled) return;
        setDiff(d);
      } catch {
        // Optional; ignore diff errors.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const findings = useMemo(() => {
    const list = data?.findings ?? [];
    return list.filter((f) => matchesQuery(f, query));
  }, [data, query]);

  if (!runId) return <div className="card">Missing run id.</div>;

  return (
    <div className="grid">
      <div className="topbar">
        <div>
          <h1 className="h1">Run Detail</h1>
          <div className="subtitle">Inspect findings, remediation, artifacts, and diffs.</div>
        </div>
        <div className="row">
          {data ? (
            <span className="pill">
              <span
                className="pillDot"
                style={{
                  background:
                    data.run.status === "completed"
                      ? "var(--good)"
                      : data.run.status === "failed"
                        ? "var(--bad)"
                        : "var(--warn)",
                }}
              />
              Status: {data.run.status}
            </span>
          ) : null}
          <Link className="btn secondary" to="/scans">
            Back to Scans
          </Link>
        </div>
      </div>

      {error ? <div className="card">Error: {error}</div> : null}
      {!data ? <div className="card">Loading…</div> : null}

      {data ? (
        <>
          {diff ? (
            <div className="card">
              <div className="cardTitle">Diff vs Previous Completed Run</div>
              <div className="muted" style={{ marginTop: 8 }}>
                Base:{" "}
                {diff.base_run_id ? <Link to={`/runs/${diff.base_run_id}`}>{diff.base_run_id}</Link> : "none"}
              </div>
              <div className="row" style={{ marginTop: 10 }}>
                <span className="badge low">New: {diff.new_findings.length}</span>
                <span className="badge info">Resolved: {diff.resolved_findings.length}</span>
              </div>
              {diff.new_findings.length ? (
                <div style={{ marginTop: 12 }}>
                  <div className="muted" style={{ marginBottom: 6 }}>
                    New findings (top 5)
                  </div>
                  <ul className="muted" style={{ margin: 0, paddingLeft: 18 }}>
                    {diff.new_findings.slice(0, 5).map((f) => (
                      <li key={f.id}>
                        <SeverityBadge severity={f.severity} /> {f.title}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}

          <div className="card">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div>
                <div style={{ fontWeight: 700 }}>{data.run.id}</div>
                <div className="muted" style={{ marginTop: 6 }}>
                  Status: <span className="badge info">{data.run.status}</span>
                  {data.run.current_scanner ? (
                    <>
                      {" "}
                      · Running:{" "}
                      <span style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas" }}>
                        {data.run.current_scanner}
                      </span>
                    </>
                  ) : null}
                </div>
                <div className="muted" style={{ marginTop: 6 }}>
                  Progress: {data.run.progress_current}/{data.run.progress_total}
                </div>
                {data.run.error ? (
                  <div style={{ marginTop: 8 }} className="badge high">
                    Error: {data.run.error}
                  </div>
                ) : null}
              </div>
              <div className="row">
                <button className="btn secondary" onClick={exportFindingsJson} disabled={!data}>
                  Export JSON
                </button>
                <input
                  placeholder="Filter findings…"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div className="card">
            <div className="cardTitle">Findings ({findings.length})</div>
            <div style={{ marginTop: 12 }}>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Title</th>
                    <th>Scanner</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="muted">{f.category}</td>
                      <td>
                        <div style={{ fontWeight: 700 }}>{f.title}</div>
                        <div className="muted" style={{ marginTop: 4 }}>
                          {f.description}
                        </div>
                        {f.remediation ? (
                          <div style={{ marginTop: 8 }}>
                            <span className="muted">Remediation:</span> {f.remediation}
                          </div>
                        ) : null}
                        {f.references.length ? (
                          <div style={{ marginTop: 8 }} className="muted">
                            Refs: {f.references.slice(0, 3).join(", ")}
                          </div>
                        ) : null}
                        <FindingResolution finding={f} />
                      </td>
                      <td className="muted">{f.scanner_id}</td>
                    </tr>
                  ))}
                  {findings.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="muted">
                        No findings match the filter.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div className="cardTitle">Artifacts</div>
            <div className="muted" style={{ marginTop: 8 }}>
              Stored keys: {Object.keys(data.artifacts).length ? Object.keys(data.artifacts).join(", ") : "none"}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
