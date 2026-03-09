from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


def _mode_octal(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def _is_too_open(mode: int) -> bool:
    # Any group/world write or read permissions on sensitive files.
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))


class SshPermissionsScanner(Scanner):
    id = "macos.ssh_permissions"
    name = "SSH Permissions Hygiene"
    description = "Checks ~/.ssh permissions (metadata only; does not read key contents)."
    category = "config"
    supported_platforms = ["darwin", "linux"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        home = Path(os.path.expanduser("~"))
        ssh_dir = home / ".ssh"
        if not ssh_dir.exists():
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="config",
                        severity="info",
                        title="No ~/.ssh directory detected",
                        description="Skipping SSH permission checks because ~/.ssh does not exist.",
                        fingerprint_parts=["ssh", "missing"],
                    )
                ],
                {},
            )

        findings: list[Any] = []
        evidence: dict[str, Any] = {"ssh_dir": str(ssh_dir), "checks": []}

        # Directory should be 700-ish; group/world bits should not be set.
        dir_mode = stat.S_IMODE(ssh_dir.stat().st_mode)
        evidence["checks"].append({"path": str(ssh_dir), "mode": oct(dir_mode), "type": "dir"})
        if _is_too_open(dir_mode):
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="high",
                    title="~/.ssh permissions are too open",
                    description=f"~/.ssh has mode {_mode_octal(ssh_dir)}; group/world permissions present.",
                    remediation="Run: chmod 700 ~/.ssh",
                    evidence=evidence_dict(path=str(ssh_dir), mode=_mode_octal(ssh_dir)),
                    fingerprint_parts=["ssh", "dir", "too_open", _mode_octal(ssh_dir)],
                )
            )

        sensitive_files: list[Path] = []
        for child in ssh_dir.iterdir():
            if child.is_dir():
                continue
            name = child.name
            # Private keys are commonly named id_* without .pub.
            if name.startswith("id_") and not name.endswith(".pub"):
                sensitive_files.append(child)
            if name in ("authorized_keys", "config", "known_hosts"):
                sensitive_files.append(child)

        checked = 0
        for file_path in sorted(set(sensitive_files))[:200]:
            checked += 1
            try:
                mode = stat.S_IMODE(file_path.stat().st_mode)
            except FileNotFoundError:
                continue
            evidence["checks"].append({"path": str(file_path), "mode": oct(mode), "type": "file"})
            if _is_too_open(mode):
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="config",
                        severity="high",
                        title=f"SSH file permissions too open: {file_path.name}",
                        description=f"{file_path} has mode {_mode_octal(file_path)}; group/world permissions present.",
                        remediation=f"Run: chmod 600 {file_path}",
                        evidence=evidence_dict(path=str(file_path), mode=_mode_octal(file_path)),
                        fingerprint_parts=["ssh", "file", "too_open", str(file_path), _mode_octal(file_path)],
                    )
                )

        if not findings:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="SSH permissions look OK (best-effort)",
                    description=f"Checked ~/.ssh and {checked} common SSH files; no overly-open permissions detected.",
                    evidence=evidence_dict(checked=checked),
                    fingerprint_parts=["ssh", "ok"],
                )
            )

        return findings, {"ssh.permissions": evidence}
