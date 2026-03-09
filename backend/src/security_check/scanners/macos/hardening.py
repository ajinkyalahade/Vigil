from __future__ import annotations

import platform
import subprocess
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


def _run(cmd: list[str], timeout_s: int = 8) -> tuple[int, str, str]:
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


class MacosHardeningScanner(Scanner):
    id = "macos.hardening"
    name = "macOS Hardening Checks"
    description = "Checks firewall, Gatekeeper, SIP, FileVault (best-effort, no sudo)."
    category = "config"
    supported_platforms = ["darwin"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        if ctx.platform != "darwin":
            return [], {}

        now = utc_now_iso()
        findings = []
        run_id = ctx.run_id

        # Firewall (Application Firewall)
        rc, out, err = _run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
        )
        firewall_enabled: bool | None = None
        if rc == 0 and out:
            firewall_enabled = "enabled" in out.lower() and "disabled" not in out.lower()
        if firewall_enabled is True:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="Application Firewall enabled",
                    description="macOS Application Firewall appears to be enabled.",
                    evidence=evidence_dict(raw=out),
                    fingerprint_parts=["firewall", "enabled"],
                )
            )
        elif firewall_enabled is False:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="high",
                    title="Application Firewall disabled",
                    description="macOS Application Firewall appears to be disabled.",
                    remediation="Enable the macOS Application Firewall in System Settings → Network → Firewall.",
                    evidence=evidence_dict(raw=out),
                    fingerprint_parts=["firewall", "disabled"],
                )
            )
        else:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="Application Firewall state unknown",
                    description="Could not determine Application Firewall state without additional permissions.",
                    evidence=evidence_dict(cmd="socketfilterfw --getglobalstate", rc=rc, out=out, err=err),
                    fingerprint_parts=["firewall", "unknown"],
                )
            )

        # Gatekeeper
        rc, out, err = _run(["spctl", "--status"])
        if rc == 0 and out:
            gatekeeper_enabled = "enabled" in out.lower()
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info" if gatekeeper_enabled else "high",
                    title="Gatekeeper enabled" if gatekeeper_enabled else "Gatekeeper disabled",
                    description=(
                        "Gatekeeper assessments appear to be enabled."
                        if gatekeeper_enabled
                        else "Gatekeeper assessments appear to be disabled."
                    ),
                    remediation=(
                        ""
                        if gatekeeper_enabled
                        else "Re-enable Gatekeeper (spctl) to reduce risk from unsigned apps."
                    ),
                    evidence=evidence_dict(raw=out),
                    fingerprint_parts=["gatekeeper", "enabled" if gatekeeper_enabled else "disabled"],
                )
            )
        else:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="Gatekeeper state unknown",
                    description="Could not determine Gatekeeper state.",
                    evidence=evidence_dict(cmd="spctl --status", rc=rc, out=out, err=err),
                    fingerprint_parts=["gatekeeper", "unknown"],
                )
            )

        # SIP
        rc, out, err = _run(["csrutil", "status"])
        if rc == 0 and out:
            sip_enabled = "enabled" in out.lower()
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info" if sip_enabled else "high",
                    title="SIP enabled" if sip_enabled else "SIP disabled",
                    description=(
                        "System Integrity Protection appears to be enabled."
                        if sip_enabled
                        else "System Integrity Protection appears to be disabled."
                    ),
                    remediation=(
                        ""
                        if sip_enabled
                        else "Re-enable SIP (requires Recovery mode) unless you have a specific need to keep it disabled."
                    ),
                    evidence=evidence_dict(raw=out),
                    fingerprint_parts=["sip", "enabled" if sip_enabled else "disabled"],
                )
            )
        else:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="SIP state unknown",
                    description="Could not determine SIP state.",
                    evidence=evidence_dict(cmd="csrutil status", rc=rc, out=out, err=err),
                    fingerprint_parts=["sip", "unknown"],
                )
            )

        # FileVault
        rc, out, err = _run(["fdesetup", "status"])
        if rc == 0 and out:
            fv_on = "on" in out.lower()
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info" if fv_on else "medium",
                    title="FileVault on" if fv_on else "FileVault off",
                    description="Full-disk encryption appears to be on." if fv_on else "Full-disk encryption appears to be off.",
                    remediation="" if fv_on else "Enable FileVault to encrypt your disk at rest.",
                    evidence=evidence_dict(raw=out),
                    fingerprint_parts=["filevault", "on" if fv_on else "off"],
                )
            )
        else:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="FileVault state unknown",
                    description="Could not determine FileVault state.",
                    evidence=evidence_dict(cmd="fdesetup status", rc=rc, out=out, err=err),
                    fingerprint_parts=["filevault", "unknown"],
                )
            )

        artifact = {"os": platform.platform(), "machine": platform.machine()}
        return findings, {"host.platform": artifact}
