from __future__ import annotations

import re
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


_TCP_LISTEN_RE = re.compile(r"TCP\s+(?P<addr>.+?)\s+\(LISTEN\)")


class ListeningPortsScanner(Scanner):
    id = "network.listening_ports"
    name = "Listening TCP Ports"
    description = "Lists local TCP listening ports via lsof (best-effort, no sudo)."
    category = "network"
    supported_platforms = ["darwin", "linux"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        rc, out, err = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if rc != 0 or not out:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="network",
                        severity="info",
                        title="Listening ports scan unavailable",
                        description="Could not list listening ports via lsof.",
                        evidence=evidence_dict(rc=rc, out=out, err=err),
                        fingerprint_parts=["ports", "error"],
                    )
                ],
                {},
            )

        lines = out.splitlines()
        header, rows = lines[0], lines[1:]
        _ = header  # unused; kept for clarity

        ports = []
        findings = []
        for line in rows[:2000]:
            # lsof columns are space-separated but command names may vary; we focus on NAME field.
            m = _TCP_LISTEN_RE.search(line)
            if not m:
                continue
            name_field = m.group("addr")
            ports.append({"raw": line, "name": name_field})

            is_exposed = False
            exposure_reason = ""
            if name_field.startswith("*:") or name_field.startswith("0.0.0.0:") or name_field.startswith("[::]:"):
                is_exposed = True
                exposure_reason = "listening on all interfaces"
            elif name_field.startswith("127.0.0.1:") or name_field.startswith("[::1]:") or name_field.startswith("localhost:"):
                is_exposed = False
            else:
                # Heuristic: unknown bind, treat as potentially exposed.
                is_exposed = True
                exposure_reason = "bind address not localhost"

            if is_exposed:
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="network",
                        severity="medium",
                        title=f"Service exposed: {name_field}",
                        description=f"A process is listening on {name_field} ({exposure_reason}).",
                        remediation="If you don't need this service reachable, bind to localhost or disable it.",
                        evidence=evidence_dict(lsof_line=line),
                        fingerprint_parts=["ports", name_field],
                    )
                )

        if not findings:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="network",
                    severity="info",
                    title="No obviously exposed listening ports detected",
                    description="No listening ports matched the exposure heuristic (best-effort).",
                    evidence=evidence_dict(sample_count=len(ports)),
                    fingerprint_parts=["ports", "none_exposed"],
                )
            )

        return findings, {"network.listening_ports": ports}
