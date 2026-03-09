from __future__ import annotations

import platform
import uuid
from dataclasses import dataclass
from typing import Any

from security_check.config import Settings
from security_check.db import Database, json_dumps, json_loads, utc_now_iso
from security_check.models import Finding, RunSummary, ScannerInfo
from security_check.scanners.base import ScanContext, Scanner
from security_check.scanners.macos.brew import HomebrewOutdatedScanner
from security_check.scanners.macos.env_secrets import EnvSecretsScanner
from security_check.scanners.macos.hardening import MacosHardeningScanner
from security_check.scanners.macos.launch_agents import LaunchAgentsScanner
from security_check.scanners.macos.shell_history import ShellHistoryScanner
from security_check.scanners.network.listening_ports import ListeningPortsScanner
from security_check.scanners.network.network_config import NetworkConfigScanner
from security_check.scanners.packages.osv_vulns import OsvPackageVulnScanner
from security_check.scanners.packages.npm import NpmGlobalInventoryScanner
from security_check.scanners.packages.pip import PipInventoryScanner
from security_check.scanners.registry import ScannerRegistry
from security_check.scanners.macos.ssh_permissions import SshPermissionsScanner


def detect_platform() -> str:
    p = platform.system().lower()
    if p.startswith("darwin") or p == "mac" or p == "macos":
        return "darwin"
    if p.startswith("linux"):
        return "linux"
    if p.startswith("windows"):
        return "windows"
    return "unknown"


def default_registry() -> ScannerRegistry:
    scanners: list[Scanner] = [
        MacosHardeningScanner(),
        SshPermissionsScanner(),
        EnvSecretsScanner(),
        ShellHistoryScanner(),
        LaunchAgentsScanner(),
        NetworkConfigScanner(),
        HomebrewOutdatedScanner(),
        PipInventoryScanner(),
        NpmGlobalInventoryScanner(),
        OsvPackageVulnScanner(),
        ListeningPortsScanner(),
    ]
    return ScannerRegistry({s.id: s for s in scanners})


@dataclass
class ScanService:
    db: Database
    settings: Settings
    registry: ScannerRegistry

    def list_scanners(self) -> list[ScannerInfo]:
        infos = []
        for s in self.registry.list():
            infos.append(
                ScannerInfo(
                    id=s.id,
                    name=s.name,
                    description=s.description,
                    category=s.category,  # type: ignore[arg-type]
                    requires_admin=getattr(s, "requires_admin", False),
                    supported_platforms=getattr(s, "supported_platforms", []),
                )
            )
        return infos

    def create_run(self, scanner_ids: list[str], options: dict[str, Any]) -> RunSummary:
        run_id = str(uuid.uuid4())
        created_at = utc_now_iso()

        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_runs (
                    id, created_at, status, error,
                    requested_scanners_json, options_json,
                    progress_current, progress_total, current_scanner
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL)
                """,
                (
                    run_id,
                    created_at,
                    "queued",
                    None,
                    json_dumps(scanner_ids),
                    json_dumps(options),
                    len(scanner_ids),
                ),
            )

        return self.get_run(run_id)

    def get_run(self, run_id: str) -> RunSummary:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
            if not row:
                raise KeyError(run_id)
            return RunSummary(
                id=row["id"],
                created_at=row["created_at"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                status=row["status"],
                error=row["error"],
                requested_scanners=json_loads(row["requested_scanners_json"]),
                options=json_loads(row["options_json"]),
                progress_current=row["progress_current"],
                progress_total=row["progress_total"],
                current_scanner=row["current_scanner"],
            )

    def list_runs(self, limit: int = 50) -> list[RunSummary]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            runs = []
            for row in rows:
                runs.append(
                    RunSummary(
                        id=row["id"],
                        created_at=row["created_at"],
                        started_at=row["started_at"],
                        finished_at=row["finished_at"],
                        status=row["status"],
                        error=row["error"],
                        requested_scanners=json_loads(row["requested_scanners_json"]),
                        options=json_loads(row["options_json"]),
                        progress_current=row["progress_current"],
                        progress_total=row["progress_total"],
                        current_scanner=row["current_scanner"],
                    )
                )
            return runs

    def get_findings(self, run_id: str) -> list[Finding]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_findings WHERE run_id = ? ORDER BY created_at ASC", (run_id,)
            ).fetchall()
            out: list[Finding] = []
            for row in rows:
                out.append(
                    Finding(
                        id=row["id"],
                        run_id=row["run_id"],
                        created_at=row["created_at"],
                        scanner_id=row["scanner_id"],
                        category=row["category"],  # type: ignore[arg-type]
                        severity=row["severity"],  # type: ignore[arg-type]
                        title=row["title"],
                        description=row["description"],
                        evidence=json_loads(row["evidence_json"]),
                        remediation=row["remediation"],
                        references=json_loads(row["references_json"]),
                        fingerprint=row["fingerprint"],
                    )
                )
            return out

    def get_artifacts(self, run_id: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT key, value_json FROM scan_artifacts WHERE run_id = ?", (run_id,)
            ).fetchall()
            artifacts: dict[str, Any] = {}
            for row in rows:
                artifacts[row["key"]] = json_loads(row["value_json"])
            return artifacts

    def find_previous_completed_run_id(self, run_id: str) -> str | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT id FROM scan_runs
                WHERE status='completed'
                  AND created_at < (SELECT created_at FROM scan_runs WHERE id=?)
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            return str(row["id"]) if row else None

    def diff_runs(self, base_run_id: str, target_run_id: str) -> tuple[list[Finding], list[Finding]]:
        base = self.get_findings(base_run_id)
        target = self.get_findings(target_run_id)

        base_by_fp = {f.fingerprint: f for f in base}
        target_by_fp = {f.fingerprint: f for f in target}

        new_fps = [fp for fp in target_by_fp.keys() if fp not in base_by_fp]
        resolved_fps = [fp for fp in base_by_fp.keys() if fp not in target_by_fp]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def sort_key(f: Finding) -> tuple[int, str]:
            return (severity_order.get(f.severity, 99), f.title)

        new_findings = sorted((target_by_fp[fp] for fp in new_fps), key=sort_key)
        resolved_findings = sorted((base_by_fp[fp] for fp in resolved_fps), key=sort_key)
        return new_findings, resolved_findings

    def _write_artifact(self, *, run_id: str, key: str, value: Any) -> None:
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_artifacts (id, run_id, created_at, key, value_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id, key) DO UPDATE SET value_json=excluded.value_json
                """,
                (str(uuid.uuid4()), run_id, utc_now_iso(), key, json_dumps(value)),
            )

    def _insert_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        with self.db.connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO scan_findings (
                    id, run_id, created_at, scanner_id, category, severity, title, description,
                    evidence_json, remediation, references_json, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.id,
                        f.run_id,
                        f.created_at,
                        f.scanner_id,
                        f.category,
                        f.severity,
                        f.title,
                        f.description,
                        json_dumps(f.evidence),
                        f.remediation,
                        json_dumps(f.references),
                        f.fingerprint,
                    )
                    for f in findings
                ],
            )

    def run_scan(self, run_id: str) -> None:
        run = self.get_run(run_id)
        scanner_ids = run.requested_scanners
        options = run.options

        with self.db.connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET status=?, started_at=?, progress_current=?, current_scanner=? WHERE id=?",
                ("running", utc_now_iso(), 0, None, run_id),
            )

        ctx = ScanContext(
            run_id=run_id,
            platform=detect_platform(),  # type: ignore[arg-type]
            options=options,
            artifacts={},
            osv_api_base=self.settings.osv_api_base,
            enable_deep_scans=self.settings.enable_deep_scans,
        )

        try:
            for i, scanner_id in enumerate(scanner_ids, start=1):
                scanner = self.registry.get(scanner_id)
                if scanner is None:
                    continue
                with self.db.connect() as conn:
                    conn.execute(
                        "UPDATE scan_runs SET progress_current=?, progress_total=?, current_scanner=? WHERE id=?",
                        (i - 1, len(scanner_ids), scanner_id, run_id),
                    )

                findings, artifacts = scanner.run(ctx)
                self._insert_findings(findings)
                for k, v in artifacts.items():
                    ctx.set_artifact(k, v)
                    self._write_artifact(run_id=run_id, key=k, value=v)

            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE scan_runs SET status=?, finished_at=?, progress_current=?, current_scanner=? WHERE id=?",
                    ("completed", utc_now_iso(), len(scanner_ids), None, run_id),
                )
        except Exception as e:  # noqa: BLE001
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE scan_runs SET status=?, finished_at=?, error=? WHERE id=?",
                    ("failed", utc_now_iso(), str(e), run_id),
                )
            raise


def select_default_scanners(registry: ScannerRegistry) -> list[str]:
    # Safe-by-default: include scanners that don't require admin and support current OS.
    current = detect_platform()
    selected: list[str] = []
    for s in registry.list():
        if getattr(s, "requires_admin", False):
            continue
        supported = getattr(s, "supported_platforms", ["darwin"])
        if supported and current not in supported:
            continue
        selected.append(s.id)
    return selected
