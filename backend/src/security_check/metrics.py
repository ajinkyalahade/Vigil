from __future__ import annotations

from datetime import datetime, timedelta, timezone

from security_check.db import Database


def _date_utc_days_ago(days: int) -> str:
    start = datetime.now(timezone.utc) - timedelta(days=days)
    return start.date().isoformat()


def counts_for_run(db: Database, run_id: str) -> tuple[dict[str, int], dict[str, int]]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM scan_findings WHERE run_id=? GROUP BY severity",
            (run_id,),
        ).fetchall()
        by_sev = {r["severity"]: int(r["c"]) for r in rows}
        rows = conn.execute(
            "SELECT category, COUNT(*) AS c FROM scan_findings WHERE run_id=? GROUP BY category",
            (run_id,),
        ).fetchall()
        by_cat = {r["category"]: int(r["c"]) for r in rows}
        return by_sev, by_cat


def severity_trends(db: Database, days: int = 30) -> list[dict[str, object]]:
    since = _date_utc_days_ago(days)
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT substr(r.created_at, 1, 10) AS day, f.severity AS severity, COUNT(*) AS c
            FROM scan_findings f
            JOIN scan_runs r ON r.id = f.run_id
            WHERE r.created_at >= ?
            GROUP BY day, severity
            ORDER BY day ASC
            """,
            (since,),
        ).fetchall()
        return [{"date": r["day"], "severity": r["severity"], "count": int(r["c"])} for r in rows]

