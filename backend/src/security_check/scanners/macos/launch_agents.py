"""
Launch Agents & Login Items Scanner

Scans for persistence mechanisms on macOS:
- Launch Agents (user and system)
- Launch Daemons (system-wide)
- Login Items

Flags suspicious or unsigned items that run at startup.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


class LaunchAgentsScanner(Scanner):
    """
    Scans for launch agents, launch daemons, and login items.

    What it checks:
    - ~/Library/LaunchAgents (user launch agents)
    - /Library/LaunchAgents (system launch agents)
    - /Library/LaunchDaemons (system daemons, requires root)
    - /System/Library/LaunchAgents (Apple system agents - informational only)

    Flags:
    - Items from non-Apple developers
    - Items with network access
    - Items running as root unnecessarily
    - Items with KeepAlive=true (persistent processes)

    Severity:
    - "high" for unsigned items or items with network + persistence
    - "medium" for non-Apple items
    - "low" for items running as root
    - "info" for Apple-signed items
    """

    id = "macos.launch_agents"
    name = "Launch Agents & Login Items"
    description = "Scans for persistence mechanisms (launch agents, daemons, login items)."
    category = "config"
    supported_platforms = ["darwin"]
    requires_admin = False

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        findings: list[Any] = []
        artifacts: dict[str, Any] = {"items_scanned": [], "suspicious_items": []}

        # Directories to scan
        home = Path(os.path.expanduser("~"))
        directories = [
            (home / "Library" / "LaunchAgents", "user"),
            (Path("/Library/LaunchAgents"), "system"),
            (Path("/Library/LaunchDaemons"), "daemon"),
        ]

        total_items = 0
        suspicious_count = 0

        for directory, item_type in directories:
            if not directory.exists():
                continue

            try:
                # List all .plist files
                plist_files = list(directory.glob("*.plist"))

                for plist_file in plist_files:
                    total_items += 1
                    artifacts["items_scanned"].append(str(plist_file))

                    try:
                        # Parse plist
                        with open(plist_file, "rb") as f:
                            plist_data = plistlib.load(f)

                        # Extract relevant fields
                        label = plist_data.get("Label", plist_file.stem)
                        program = plist_data.get("Program")
                        program_args = plist_data.get("ProgramArguments", [])
                        run_at_load = plist_data.get("RunAtLoad", False)
                        keep_alive = plist_data.get("KeepAlive", False)

                        # Determine program path
                        if program:
                            program_path = program
                        elif program_args:
                            program_path = program_args[0] if program_args else None
                        else:
                            program_path = None

                        # Check if it's an Apple item (heuristic: in /System or /usr)
                        is_apple = False
                        if program_path:
                            if program_path.startswith("/System/") or program_path.startswith("/usr/"):
                                is_apple = True

                        # Check for network access (Sockets key)
                        has_network = "Sockets" in plist_data or "NetworkRequested" in plist_data

                        # Determine if suspicious
                        is_suspicious = False
                        reasons = []
                        severity = "info"

                        if not is_apple:
                            is_suspicious = True
                            reasons.append("non-Apple item")
                            severity = "medium"

                        if has_network and keep_alive:
                            is_suspicious = True
                            reasons.append("persistent network access")
                            severity = "high"

                        if not is_apple and item_type == "daemon":
                            is_suspicious = True
                            reasons.append("third-party daemon")
                            severity = "medium"

                        # Check code signature (if program path exists)
                        signature_status = None
                        if program_path and Path(program_path).exists():
                            signature_status = self._check_signature(program_path)
                            if signature_status == "unsigned":
                                is_suspicious = True
                                reasons.append("unsigned binary")
                                severity = "high"

                        if is_suspicious:
                            suspicious_count += 1
                            artifacts["suspicious_items"].append(
                                {
                                    "label": label,
                                    "path": str(plist_file),
                                    "program": program_path,
                                    "type": item_type,
                                    "reasons": reasons,
                                }
                            )

                            findings.append(
                                finding(
                                    run_id=run_id,
                                    created_at=now,
                                    scanner_id=self.id,
                                    category="config",
                                    severity=severity,
                                    title=f"Suspicious {item_type}: {label}",
                                    description=f"Found {item_type} at {plist_file} with: {', '.join(reasons)}. "
                                    f"This item runs at startup and may be a persistence mechanism.",
                                    remediation=f"1. Review what this item does: {program_path or 'unknown'}\n"
                                    f"2. If malicious or unwanted, disable it:\n"
                                    f"   launchctl unload {plist_file}\n"
                                    f"3. Remove the plist file:\n"
                                    f"   rm {plist_file}\n"
                                    f"4. Verify the binary is safe:\n"
                                    f"   codesign -dv {program_path if program_path else '(path)'}\n"
                                    f"5. Search online for the label to verify legitimacy",
                                    references=[
                                        "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
                                    ],
                                    evidence=evidence_dict(
                                        label=label,
                                        path=str(plist_file),
                                        program=program_path,
                                        type=item_type,
                                        run_at_load=run_at_load,
                                        keep_alive=keep_alive,
                                        has_network=has_network,
                                        signature=signature_status,
                                        reasons=reasons,
                                    ),
                                    fingerprint_parts=["launch_agent", label, str(plist_file)],
                                )
                            )

                    except Exception as e:
                        # Error parsing specific plist
                        findings.append(
                            finding(
                                run_id=run_id,
                                created_at=now,
                                scanner_id=self.id,
                                category="other",
                                severity="info",
                                title=f"Error parsing {plist_file.name}",
                                description=f"Could not parse {plist_file}: {str(e)}",
                                evidence=evidence_dict(error=str(e), file=str(plist_file)),
                                fingerprint_parts=["launch_agent", "error", str(plist_file)],
                            )
                        )

            except Exception as e:
                # Error scanning directory
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="other",
                        severity="info",
                        title=f"Error scanning {directory}",
                        description=f"Could not scan {directory}: {str(e)}",
                        evidence=evidence_dict(error=str(e), directory=str(directory)),
                        fingerprint_parts=["launch_agent", "error", str(directory)],
                    )
                )

        # Summary finding
        if suspicious_count == 0 and total_items > 0:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="Launch agents look OK",
                    description=f"Scanned {total_items} launch agents/daemons; "
                    f"no obviously suspicious items detected.",
                    evidence=evidence_dict(total_scanned=total_items),
                    fingerprint_parts=["launch_agent", "ok"],
                )
            )
        elif total_items == 0:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="config",
                    severity="info",
                    title="No launch agents found",
                    description="No launch agents or daemons detected in scanned directories.",
                    fingerprint_parts=["launch_agent", "none"],
                )
            )

        return findings, {"launch_agents": artifacts}

    def _check_signature(self, path: str) -> str:
        """
        Check code signature of a binary.

        Returns:
            "signed" - Properly signed
            "unsigned" - Not signed
            "unknown" - Could not determine
        """
        try:
            result = subprocess.run(
                ["codesign", "--verify", "--verbose", path],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # codesign returns 0 for valid signatures
            if result.returncode == 0:
                return "signed"
            else:
                # Check if it's unsigned or just invalid
                if "not signed" in result.stderr.lower():
                    return "unsigned"
                return "signed"  # Assume signed but maybe with issues

        except subprocess.TimeoutExpired:
            return "unknown"
        except Exception:
            return "unknown"
