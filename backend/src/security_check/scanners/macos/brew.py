from __future__ import annotations

import json
import subprocess
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


def _run(cmd: list[str], timeout_s: int = 20) -> tuple[int, str, str]:
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


class HomebrewOutdatedScanner(Scanner):
    id = "pkg.brew.outdated"
    name = "Homebrew Outdated Packages"
    description = "Lists outdated Homebrew formulae/casks (not a CVE check)."
    category = "inventory"
    supported_platforms = ["darwin"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        if ctx.platform != "darwin":
            return [], {}

        now = utc_now_iso()
        run_id = ctx.run_id

        rc, _, _ = _run(["brew", "--version"])
        if rc != 0:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="info",
                        title="Homebrew not detected",
                        description="brew was not found on PATH; skipping Homebrew checks.",
                        fingerprint_parts=["brew", "missing"],
                    )
                ],
                {},
            )

        rc, out, err = _run(["brew", "outdated", "--json=v2"])
        if rc != 0 or not out:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="info",
                        title="Homebrew outdated check unavailable",
                        description="Could not list outdated Homebrew packages.",
                        evidence=evidence_dict(rc=rc, out=out, err=err),
                        fingerprint_parts=["brew", "outdated", "error"],
                    )
                ],
                {},
            )

        data = json.loads(out)
        outdated = []
        for item in data.get("formulae", []):
            name = item.get("name")
            installed = item.get("installed_versions") or []
            current = item.get("current_version")
            if not name or not installed or not current:
                continue
            outdated.append({"type": "formula", "name": name, "installed": installed, "current": current})
        for item in data.get("casks", []):
            name = item.get("name")
            installed = item.get("installed_versions") or []
            current = item.get("current_version")
            if not name or not installed or not current:
                continue
            outdated.append({"type": "cask", "name": name, "installed": installed, "current": current})

        findings = []
        if not outdated:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="inventory",
                    severity="info",
                    title="No outdated Homebrew packages detected",
                    description="brew reports no outdated formulae/casks.",
                    fingerprint_parts=["brew", "outdated", "none"],
                )
            )
        else:
            for pkg in outdated[:200]:
                name = pkg["name"]
                installed_versions = ",".join(pkg["installed"])
                current = pkg["current"]
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="inventory",
                        severity="low",
                        title=f"Outdated {pkg['type']}: {name}",
                        description=f"Installed: {installed_versions}. Latest: {current}.",
                        remediation="Update outdated packages (brew upgrade) to reduce risk from known bugs/vulns.",
                        evidence=evidence_dict(package=pkg),
                        fingerprint_parts=["brew", "outdated", pkg["type"], name, installed_versions, current],
                    )
                )

        return findings, {"packages.brew.outdated": outdated}
