from __future__ import annotations

import json
import subprocess
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


def _run(cmd: list[str], timeout_s: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


class NpmGlobalInventoryScanner(Scanner):
    id = "pkg.npm.global_inventory"
    name = "npm Global Inventory"
    description = "Lists globally installed npm packages (npm ls -g --depth=0)."
    category = "inventory"
    supported_platforms = ["darwin", "linux", "windows"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        rc, _, _ = _run(["npm", "--version"])
        if rc != 0:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="info",
                        title="npm not detected",
                        description="npm was not found on PATH; skipping npm checks.",
                        fingerprint_parts=["npm", "missing"],
                    )
                ],
                {},
            )

        rc, out, err = _run(["npm", "ls", "-g", "--depth=0", "--json"])
        if rc not in (0, 1) or not out:
            # npm may return 1 if it reports problems; we still may get JSON.
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="info",
                        title="npm inventory unavailable",
                        description="Could not list global npm packages.",
                        evidence=evidence_dict(rc=rc, out=out, err=err),
                        fingerprint_parts=["npm", "inventory", "error"],
                    )
                ],
                {},
            )

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = {}

        deps = (data.get("dependencies") or {}) if isinstance(data, dict) else {}
        packages = []
        for name, meta in deps.items():
            version = ""
            if isinstance(meta, dict):
                version = (meta.get("version") or "").strip()
            if not name or not version:
                continue
            packages.append({"name": name, "version": version, "ecosystem": "npm"})

        return (
            [
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="inventory",
                    severity="info",
                    title="Global npm packages inventoried",
                    description=f"Collected {len(packages)} global npm packages.",
                    evidence=evidence_dict(count=len(packages)),
                    fingerprint_parts=["npm", "inventory", "summary"],
                )
            ],
            {"packages.npm": packages},
        )
