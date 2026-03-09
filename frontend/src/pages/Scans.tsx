import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiCreateRun, apiListRuns, apiListScanners } from "../api/client";
import { IconScan } from "../components/Icons";
import type { RunSummary, ScannerInfo } from "../types";

export default function Scans() {
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<boolean>(false);
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [s, r] = await Promise.all([apiListScanners(), apiListRuns(20)]);
        if (cancelled) return;
        setScanners(s);
        setRuns(r);
        setSelected(Object.fromEntries(s.map((x) => [x.id, true])));
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const selectedIds = useMemo(
    () => scanners.filter((s) => selected[s.id]).map((s) => s.id),
    [scanners, selected],
  );

  async function runScan() {
    setError(null);
    setRunning(true);
    try {
      const run = await apiCreateRun({ scanner_ids: selectedIds });
      navigate(`/runs/${run.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="grid">
      <div className="topbar">
        <div>
          <h1 className="h1">Scans</h1>
          <div className="subtitle">Select scanners, run a scan, and review findings.</div>
        </div>
        <div className="row">
          <span className="pill">
            <span className="pillDot" />
            Selected: {selectedIds.length}
          </span>
          <button className="btn" onClick={runScan} disabled={running || selectedIds.length === 0}>
            {running ? "Starting…" : "Run Scan"}
          </button>
        </div>
      </div>

      {error ? <div className="card">Error: {error}</div> : null}

      <div className="callout">
        <div className="calloutLeft">
          <div className="calloutIcon" aria-hidden>
            <IconScan size={18} />
          </div>
          <div>
            <div className="calloutTitle">Safe-by-default scanning.</div>
            <div className="calloutText">
              Scanners focus on versions, settings, permissions, and ports. No secret-content reads by default.
            </div>
          </div>
        </div>
        <Link className="btn secondary" to="/settings">
          Settings
        </Link>
      </div>

      <div className="card">
        <div className="cardTitle">Available Scanners</div>
        <div style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: 44 }}>Run</th>
                <th>Scanner</th>
                <th>Category</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {scanners.map((s) => (
                <tr key={s.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={Boolean(selected[s.id])}
                      onChange={(e) =>
                        setSelected((prev) => ({ ...prev, [s.id]: e.target.checked }))
                      }
                    />
                  </td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{s.name}</div>
                    <div className="muted" style={{ marginTop: 4 }}>
                      {s.id}
                    </div>
                  </td>
                  <td>{s.category}</td>
                  <td className="muted">
                    {s.requires_admin ? "Requires admin" : "No admin"} ·{" "}
                    {s.supported_platforms.join(", ") || "unknown"}
                  </td>
                </tr>
              ))}
              {scanners.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
                    No scanners found.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="cardTitle">Recent Runs</div>
        <div style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Created</th>
                <th>Scanners</th>
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
                  <td className="muted">{r.requested_scanners.length}</td>
                </tr>
              ))}
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="muted">
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
