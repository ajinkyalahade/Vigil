import { useEffect, useState } from "react";
import { apiHealth } from "../api/client";
import { getApiBase, getApiToken, setApiBase, setApiToken } from "../api/storage";

export default function Settings() {
  const [apiBase, setApiBaseState] = useState<string>(getApiBase());
  const [token, setTokenState] = useState<string>(getApiToken() ?? "");
  const [health, setHealth] = useState<string>("unknown");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const h = await apiHealth();
        if (cancelled) return;
        setHealth(h.status);
      } catch (e) {
        if (cancelled) return;
        setHealth("unreachable");
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
          <h1 className="h1">Settings</h1>
          <div className="subtitle">Configure API base URL and optional auth token.</div>
        </div>
        <span className="pill">
          <span className="pillDot" style={{ background: health === "ok" ? "var(--good)" : "var(--bad)" }} />
          API: {health}
        </span>
      </div>

      {error ? <div className="card">Note: {error}</div> : null}

      <div className="card">
        <div className="cardTitle">API Connection</div>
        <div style={{ marginTop: 12 }} className="grid">
          <label>
            <div className="muted" style={{ marginBottom: 6 }}>
              API Base URL
            </div>
            <input
              value={apiBase}
              onChange={(e) => setApiBaseState(e.target.value)}
              placeholder="http://127.0.0.1:8000"
              style={{ width: "100%" }}
            />
          </label>

          <label>
            <div className="muted" style={{ marginBottom: 6 }}>
              API Token (optional)
            </div>
            <input
              value={token}
              onChange={(e) => setTokenState(e.target.value)}
              placeholder="Bearer token"
              style={{ width: "100%" }}
            />
          </label>

          <div className="row">
            <button
              className="btn"
              onClick={() => {
                setApiBase(apiBase);
                setApiToken(token);
                window.location.reload();
              }}
            >
              Save & Reload
            </button>
            <button
              className="btn secondary"
              onClick={() => {
                setApiBaseState(getApiBase());
                setTokenState(getApiToken() ?? "");
              }}
            >
              Reset
            </button>
          </div>
          <div className="muted" style={{ fontSize: 12 }}>
            Tip: backend token auth is disabled unless `SC_API_TOKEN` is set.
          </div>
        </div>
      </div>
    </div>
  );
}
