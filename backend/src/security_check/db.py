from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class Database:
    path: Path

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(
                """
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    error TEXT,
                    requested_scanners_json TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    progress_current INTEGER NOT NULL DEFAULT 0,
                    progress_total INTEGER NOT NULL DEFAULT 0,
                    current_scanner TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    scanner_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_findings_run_id ON scan_findings(run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON scan_findings(fingerprint);

                CREATE TABLE IF NOT EXISTS scan_artifacts (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON scan_artifacts(run_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_run_key ON scan_artifacts(run_id, key);

                CREATE TABLE IF NOT EXISTS finding_resolutions (
                    id TEXT PRIMARY KEY,
                    finding_fingerprint TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,

                    -- AI-generated content
                    analysis TEXT NOT NULL,
                    steps_json TEXT NOT NULL,
                    safety_notes_json TEXT NOT NULL,
                    verification_json TEXT,
                    references_json TEXT NOT NULL,
                    confidence TEXT NOT NULL,

                    -- User interaction
                    status TEXT NOT NULL DEFAULT 'pending',
                    user_feedback TEXT,
                    feedback_notes TEXT,
                    applied_at TEXT,

                    -- Metadata
                    model_used TEXT NOT NULL,
                    tokens_used INTEGER,
                    latency_ms INTEGER,

                    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_resolutions_fingerprint ON finding_resolutions(finding_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_resolutions_finding ON finding_resolutions(finding_id);
                CREATE INDEX IF NOT EXISTS idx_resolutions_status ON finding_resolutions(status);

                CREATE TABLE IF NOT EXISTS execution_sessions (
                    id              TEXT PRIMARY KEY,
                    resolution_id   TEXT NOT NULL,
                    finding_id      TEXT NOT NULL,
                    run_id          TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    current_step    INTEGER NOT NULL DEFAULT 0,
                    steps_state     TEXT NOT NULL DEFAULT '[]',
                    abort_reason    TEXT,
                    FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_resolution ON execution_sessions(resolution_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_finding ON execution_sessions(finding_id);
                """
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        finally:
            conn.close()


def json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def json_loads(value: str) -> Any:
    return json.loads(value)

