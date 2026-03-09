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


class PipInventoryScanner(Scanner):
    id = "pkg.pypi.inventory"
    name = "Python (pip) Inventory"
    description = "Lists packages from `python3 -m pip list` in the backend environment."
    category = "inventory"
    supported_platforms = ["darwin", "linux", "windows"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        rc, out, err = _run(["python3", "-m", "pip", "list", "--format=json"])
        if rc != 0 or not out:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="info",
                        title="pip inventory unavailable",
                        description="Could not list pip packages. Is python3/pip installed?",
                        evidence=evidence_dict(rc=rc, out=out, err=err),
                        fingerprint_parts=["pip", "inventory", "error"],
                    )
                ],
                {},
            )

        try:
            pkgs = json.loads(out)
        except json.JSONDecodeError:
            pkgs = []

        packages = []
        for p in pkgs or []:
            name = (p.get("name") or "").strip()
            version = (p.get("version") or "").strip()
            if not name or not version:
                continue
            packages.append({"name": name, "version": version, "ecosystem": "PyPI"})

        summary = {
            "count": len(packages),
        }
        return (
            [
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="inventory",
                    severity="info",
                    title="pip packages inventoried",
                    description=f"Collected {len(packages)} Python packages from pip.",
                    evidence=evidence_dict(summary=summary),
                    fingerprint_parts=["pip", "inventory", "summary"],
                )
            ],
            {"packages.pypi": packages},
        )
