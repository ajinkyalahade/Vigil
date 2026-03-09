"""
Environment Variable Secrets Scanner

Scans shell configuration files for potentially exposed secrets.
METADATA ONLY - does not capture actual secret values.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding

# Patterns that likely indicate secrets
SECRET_PATTERNS = [
    (r"AWS_SECRET_ACCESS_KEY\s*=", "AWS Secret Access Key"),
    (r"AWS_ACCESS_KEY_ID\s*=", "AWS Access Key ID"),
    (r"\w*_?API_KEY\s*=", "API Key"),
    (r"\w*_?TOKEN\s*=", "Token"),
    (r"\w*_?PASSWORD\s*=", "Password"),
    (r"\w*_?SECRET\s*=", "Secret"),
    (r"GITHUB_TOKEN\s*=", "GitHub Token"),
    (r"GITLAB_TOKEN\s*=", "GitLab Token"),
    (r"OPENAI_API_KEY\s*=", "OpenAI API Key"),
    (r"ANTHROPIC_API_KEY\s*=", "Anthropic API Key"),
    (r"STRIPE_SECRET_KEY\s*=", "Stripe Secret Key"),
    (r"DATABASE_URL\s*=\s*['\"]?[a-z]+://[^:]+:[^@]+@", "Database URL with credentials"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),
]


class EnvSecretsScanner(Scanner):
    """
    Scans shell configuration files for exposed secrets in environment variables.

    What it checks:
    - ~/.bashrc, ~/.zshrc, ~/.profile, ~/.bash_profile, ~/.zshenv
    - Looks for patterns indicating secrets (API keys, tokens, passwords)
    - METADATA ONLY: Never captures actual secret values

    Severity:
    - "high" for AWS keys, private keys, database URLs with credentials
    - "medium" for API keys, tokens
    - "low" for generic password variables
    """

    id = "macos.env_secrets"
    name = "Environment Variable Secrets"
    description = "Scans shell configs for exposed secrets (metadata only, no secret values captured)."
    category = "secrets"
    supported_platforms = ["darwin", "linux"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        home = Path(os.path.expanduser("~"))
        config_files = [
            home / ".bashrc",
            home / ".zshrc",
            home / ".profile",
            home / ".bash_profile",
            home / ".zshenv",
        ]

        findings: list[Any] = []
        artifacts: dict[str, Any] = {"files_scanned": [], "secrets_found": []}

        for config_file in config_files:
            if not config_file.exists():
                continue

            artifacts["files_scanned"].append(str(config_file))

            try:
                # Read file content
                content = config_file.read_text(errors="ignore")
                lines = content.splitlines()

                # Scan each line for secret patterns
                for line_num, line in enumerate(lines, start=1):
                    # Skip comments
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue

                    # Check against secret patterns
                    for pattern, description in SECRET_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Redact the actual value - only capture metadata
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                variable_name = match.group(0).split("=")[0].strip()

                                # Determine severity based on type
                                severity = self._determine_severity(description)

                                # Build redacted context (show first few chars before =)
                                context_start = max(0, match.start() - 10)
                                context_end = min(len(line), match.end() + 10)
                                redacted_context = (
                                    line[context_start : match.end()] + "***REDACTED***"
                                )

                                findings.append(
                                    finding(
                                        run_id=run_id,
                                        created_at=now,
                                        scanner_id=self.id,
                                        category="secrets",
                                        severity=severity,
                                        title=f"{description} in {config_file.name}",
                                        description=f"Found potential {description.lower()} in {config_file} at line {line_num}. "
                                        f"This secret may be exposed to all processes.",
                                        remediation=f"1. Rotate/invalidate this credential\n"
                                        f"2. Remove from {config_file}\n"
                                        f"3. Store securely (use .env file, macOS Keychain, or secret manager)\n"
                                        f"4. Consider using tools like direnv for per-project secrets",
                                        references=[
                                            "https://www.12factor.net/config",
                                            "https://direnv.net/",
                                        ],
                                        evidence=evidence_dict(
                                            file=str(config_file),
                                            line_number=line_num,
                                            variable_name=variable_name,
                                            pattern_matched=description,
                                            # NEVER include actual secret value
                                            redacted_context=redacted_context[:50],
                                        ),
                                        fingerprint_parts=[
                                            "env_secret",
                                            str(config_file),
                                            variable_name,
                                        ],
                                    )
                                )

                                artifacts["secrets_found"].append(
                                    {
                                        "file": str(config_file),
                                        "line": line_num,
                                        "type": description,
                                    }
                                )

            except Exception as e:
                # Log error but don't fail the scan
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="other",
                        severity="info",
                        title=f"Error scanning {config_file.name}",
                        description=f"Could not scan {config_file}: {str(e)}",
                        evidence=evidence_dict(error=str(e)),
                        fingerprint_parts=["env_secret", "error", str(config_file)],
                    )
                )

        # Summary finding if no secrets found
        if not any(f.get("category") == "secrets" for f in findings):
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="secrets",
                    severity="info",
                    title="No obvious secrets found in shell configs",
                    description=f"Scanned {len(artifacts['files_scanned'])} shell configuration files; "
                    f"no obvious secret patterns detected.",
                    evidence=evidence_dict(files_scanned=len(artifacts["files_scanned"])),
                    fingerprint_parts=["env_secret", "none_found"],
                )
            )

        return findings, {"env_secrets": artifacts}

    def _determine_severity(self, description: str) -> str:
        """Determine severity based on secret type."""
        high_severity = ["AWS Secret", "AWS Access", "Private Key", "Database URL"]
        low_severity = ["Password"]

        for keyword in high_severity:
            if keyword in description:
                return "high"

        for keyword in low_severity:
            if keyword in description:
                return "low"

        return "medium"  # Default for API keys, tokens, etc.
