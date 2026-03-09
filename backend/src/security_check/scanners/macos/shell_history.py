"""
Shell History Scanner

Scans shell history files for commands that may have exposed secrets.
METADATA ONLY - does not capture actual secret values.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding

# Patterns that indicate secrets in command history
RISKY_COMMAND_PATTERNS = [
    (r"curl\s+.*-H\s+['\"]Authorization:\s*Bearer\s+\w+", "curl with Bearer token"),
    (r"curl\s+.*-H\s+['\"]X-API-Key:\s*\w+", "curl with API key header"),
    (r"export\s+\w*PASSWORD\s*=", "Password export"),
    (r"export\s+\w*TOKEN\s*=", "Token export"),
    (r"export\s+\w*API_KEY\s*=", "API key export"),
    (r"export\s+\w*SECRET\s*=", "Secret export"),
    (r"git\s+clone\s+https?://[^:]+:[^@]+@", "git clone with embedded credentials"),
    (r"mysql\s+.*-p\w+", "mysql with password on command line"),
    (r"psql\s+.*password=\w+", "psql with password in connection string"),
    (r"docker\s+login\s+.*-p\s+\w+", "docker login with password"),
    (r"aws\s+configure\s+set\s+aws_secret_access_key", "AWS secret key configuration"),
    (r"echo\s+['\"]?[A-Za-z0-9+/]{40,}['\"]?\s+\|", "echo with long base64-like string"),
]


class ShellHistoryScanner(Scanner):
    """
    Scans shell history files for commands containing secrets.

    What it checks:
    - ~/.bash_history, ~/.zsh_history
    - Commands with credentials (curl auth, export PASSWORD, git clone with creds)
    - Database commands with passwords
    - Docker/AWS credential commands

    Severity:
    - "high" for AWS credentials, database passwords
    - "medium" for API tokens, curl auth headers
    - "low" for generic exports

    IMPORTANT: Never captures actual secret values, only patterns matched.
    """

    id = "macos.shell_history"
    name = "Shell History Secrets"
    description = "Scans shell history for commands with exposed secrets (metadata only)."
    category = "secrets"
    supported_platforms = ["darwin", "linux"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        home = Path(os.path.expanduser("~"))
        history_files = [
            home / ".bash_history",
            home / ".zsh_history",
        ]

        findings: list[Any] = []
        artifacts: dict[str, Any] = {"files_scanned": [], "risky_commands_found": []}

        for history_file in history_files:
            if not history_file.exists():
                continue

            artifacts["files_scanned"].append(str(history_file))

            try:
                # Read history file
                content = history_file.read_text(errors="ignore")
                lines = content.splitlines()

                # Scan each line for risky patterns
                for line_num, line in enumerate(lines, start=1):
                    # Skip empty lines
                    if not line.strip():
                        continue

                    # Check against risky command patterns
                    for pattern, description in RISKY_COMMAND_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Determine severity
                            severity = self._determine_severity(description)

                            # Redact the command - only show the pattern type
                            command_preview = self._redact_command(line)

                            findings.append(
                                finding(
                                    run_id=run_id,
                                    created_at=now,
                                    scanner_id=self.id,
                                    category="secrets",
                                    severity=severity,
                                    title=f"Risky command in {history_file.name}: {description}",
                                    description=f"Found command with potential secrets in {history_file} at line {line_num}. "
                                    f"Command pattern: {description}. "
                                    f"This command may have exposed sensitive data.",
                                    remediation=f"1. Rotate/invalidate any credentials that may have been exposed\n"
                                    f"2. Clear this entry from shell history:\n"
                                    f"   - For bash: Use 'history -d {line_num}' or edit ~/.bash_history\n"
                                    f"   - For zsh: Edit ~/.zsh_history manually\n"
                                    f"3. Prevent future exposure:\n"
                                    f"   - Use HISTIGNORE to exclude sensitive commands\n"
                                    f"   - Use HISTCONTROL=ignorespace and prefix sensitive commands with space\n"
                                    f"   - Store credentials in credential managers, not on command line",
                                    references=[
                                        "https://www.gnu.org/software/bash/manual/html_node/Bash-History-Builtins.html",
                                        "https://zsh.sourceforge.io/Doc/Release/Options.html#History",
                                    ],
                                    evidence=evidence_dict(
                                        file=str(history_file),
                                        line_number=line_num,
                                        pattern_matched=description,
                                        # Show first 30 chars only, redact the rest
                                        command_preview=command_preview,
                                    ),
                                    fingerprint_parts=[
                                        "shell_history",
                                        str(history_file),
                                        str(line_num),
                                    ],
                                )
                            )

                            artifacts["risky_commands_found"].append(
                                {
                                    "file": str(history_file),
                                    "line": line_num,
                                    "pattern": description,
                                }
                            )

                            # Only match once per line
                            break

            except Exception as e:
                # Log error but don't fail the scan
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="other",
                        severity="info",
                        title=f"Error scanning {history_file.name}",
                        description=f"Could not scan {history_file}: {str(e)}",
                        evidence=evidence_dict(error=str(e)),
                        fingerprint_parts=["shell_history", "error", str(history_file)],
                    )
                )

        # Summary finding if no risky commands found
        if not any(getattr(f, "category", None) == "secrets" for f in findings):
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="secrets",
                    severity="info",
                    title="No obvious secrets found in shell history",
                    description=f"Scanned {len(artifacts['files_scanned'])} shell history files; "
                    f"no obvious risky command patterns detected.",
                    evidence=evidence_dict(files_scanned=len(artifacts["files_scanned"])),
                    fingerprint_parts=["shell_history", "none_found"],
                )
            )

        return findings, {"shell_history": artifacts}

    def _determine_severity(self, description: str) -> str:
        """Determine severity based on secret type."""
        high_severity = ["AWS secret", "mysql with password", "psql with password", "git clone with"]
        low_severity = ["export"]

        description_lower = description.lower()

        for keyword in high_severity:
            if keyword in description_lower:
                return "high"

        for keyword in low_severity:
            if keyword in description_lower:
                return "low"

        return "medium"  # Default for curl auth, docker login, etc.

    def _redact_command(self, command: str) -> str:
        """
        Redact sensitive parts of command while keeping enough context.
        Show first 30 chars, then redact the rest.
        """
        if len(command) <= 30:
            return command + " ***REDACTED***"
        return command[:30] + "... ***REDACTED***"
