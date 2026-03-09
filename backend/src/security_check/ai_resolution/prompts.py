"""
Prompt templates for AI resolution generation.
Category-specific prompts for different finding types.
"""

from typing import Any

SYSTEM_PROMPT = """You are a security remediation expert helping users fix security issues on their macOS systems.

Your role is to:
1. Analyze security findings and identify root causes
2. Provide safe, step-by-step remediation instructions
3. Include verification steps to confirm fixes work
4. Warn about potential side effects or prerequisites

Safety rules:
- NEVER suggest destructive commands like `rm -rf /` or similar
- NEVER suggest commands with unvalidated user input
- NEVER suggest downloading and executing remote scripts without explanation
- ALWAYS include verification steps
- ALWAYS provide rollback instructions where applicable
- ALWAYS warn about potential impacts

Response format:
You must respond with valid JSON matching this structure:
{
  "analysis": "Brief root cause explanation",
  "steps": [
    {
      "order": 1,
      "description": "What this step does",
      "command": "command to run",
      "expected_output": "what output should show",
      "is_safe": true,
      "requires_confirmation": false
    }
  ],
  "safety_notes": ["Warning about side effects"],
  "verification": {
    "command": "command to verify fix",
    "expected_output": "what success looks like"
  },
  "references": ["https://relevant-docs.com"],
  "confidence": "high"
}
"""


def build_config_prompt(
    finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """Build prompt for configuration-related findings (SSH, firewall, etc.)."""
    ctx = context or {}

    return f"""
Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Description: {finding.get('description', '')}
- Category: {finding.get('category', 'config')}
- Severity: {finding.get('severity', 'unknown')}
- Evidence: {finding.get('evidence', dict())}

System Context:
- OS: {ctx.get('os_version', 'macOS (version unknown)')}
- User: {ctx.get('username', 'unknown')}
{f"- Additional Info: {ctx['additional_info']}" if ctx.get('additional_info') else ""}

Task: Generate a safe, step-by-step resolution for this configuration issue.

Focus on:
1. Analyzing why this configuration is insecure
2. Providing commands to verify current state (read-only)
3. Providing commands to fix the configuration
4. Including verification after the fix
5. Warning about any impacts (e.g., service restarts, permission changes)

For file permission issues:
- Use chmod/chown commands only
- Show current vs desired permissions clearly
- Explain why the permissions are needed

For system settings:
- Show how to check current setting
- Show command to change it
- Explain what the setting controls
"""


def build_vuln_prompt(
    finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """Build prompt for vulnerability-related findings (CVEs, outdated packages)."""
    ctx = context or {}
    evidence = finding.get("evidence", {})
    package_name = evidence.get("package", {}).get("name", "unknown")
    current_version = evidence.get("package", {}).get("version", "unknown")

    return f"""
Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Description: {finding.get('description', '')}
- Category: {finding.get('category', 'vuln')}
- Severity: {finding.get('severity', 'unknown')}
- Package: {package_name}
- Current Version: {current_version}
- Evidence: {evidence}

System Context:
- OS: {ctx.get('os_version', 'macOS (version unknown)')}
{f"- Additional Info: {ctx['additional_info']}" if ctx.get('additional_info') else ""}

Task: Generate a safe package update plan to address this vulnerability.

Focus on:
1. Explaining the vulnerability and its impact
2. Checking if the package is actually in use
3. Providing update commands for the package manager (brew, pip, npm)
4. Warning about potential breaking changes
5. Suggesting how to test after update
6. Providing rollback instructions if needed

For Homebrew packages:
- Use `brew upgrade <package>`
- Mention `brew pin` for holding versions if needed

For pip packages:
- Use `pip install --upgrade <package>`
- Suggest using virtual environments

For npm packages:
- Use `npm update <package>` or `npm install <package>@latest`
- Warn about checking package-lock.json
"""


def build_secrets_prompt(
    finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """Build prompt for secrets-related findings (credentials in env, history, etc.)."""
    ctx = context or {}

    return f"""
Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Description: {finding.get('description', '')}
- Category: {finding.get('category', 'secrets')}
- Severity: {finding.get('severity', 'unknown')}
- Evidence: {finding.get('evidence', dict())}

System Context:
- OS: {ctx.get('os_version', 'macOS (version unknown)')}
- User: {ctx.get('username', 'unknown')}
{f"- Additional Info: {ctx['additional_info']}" if ctx.get('additional_info') else ""}

Task: Generate a safe plan to remediate this secrets exposure.

CRITICAL: This finding involves credentials or secrets. Focus on secure handling.

Steps should include:
1. Rotating/invalidating the exposed credential
2. Removing the secret from the insecure location
3. Storing it properly (environment variable in secure config, password manager, keychain)
4. Preventing future exposure (add to .gitignore, use secret management tools)

For environment variables in shell configs:
- Recommend using .env files (not checked into git)
- Suggest using direnv or similar tools
- Show how to move secret to macOS Keychain

For shell history:
- Suggest clearing history or specific lines
- Recommend using HISTIGNORE or HISTCONTROL
- Emphasize that the secret should be rotated

For git repos:
- Recommend git-secrets or similar tools
- Suggest rewriting history if secret was committed (with warnings)
- Provide instructions to invalidate exposed credentials

NEVER include actual secret values in your response.
"""


def build_network_prompt(
    finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """Build prompt for network-related findings (open ports, proxies, etc.)."""
    ctx = context or {}

    return f"""
Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Description: {finding.get('description', '')}
- Category: {finding.get('category', 'network')}
- Severity: {finding.get('severity', 'unknown')}
- Evidence: {finding.get('evidence', dict())}

System Context:
- OS: {ctx.get('os_version', 'macOS (version unknown)')}
{f"- Additional Info: {ctx['additional_info']}" if ctx.get('additional_info') else ""}

Task: Generate a safe plan to address this network security issue.

Focus on:
1. Identifying what service is listening/connected
2. Determining if the service is necessary
3. Providing options:
   a. Change binding to localhost if external access not needed
   b. Configure firewall rules to restrict access
   c. Disable/stop the service if not needed
4. Verification steps to confirm changes

For listening ports:
- Show how to identify the process (lsof, netstat)
- Explain configuration changes for common services
- Show macOS firewall configuration (pfctl or System Preferences)

For proxy/DNS issues:
- Show how to check current settings (networksetup, scutil)
- Provide commands to change settings
- Explain security implications

For open Wi-Fi:
- Recommend using VPN
- Warn about MITM risks
- Suggest switching to secure network
"""


def build_inventory_prompt(
    finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """Build prompt for inventory-related findings (informational, typically no fix needed)."""
    ctx = context or {}

    return f"""
Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Description: {finding.get('description', '')}
- Category: {finding.get('category', 'inventory')}
- Severity: {finding.get('severity', 'info')}
- Evidence: {finding.get('evidence', dict())}

System Context:
- OS: {ctx.get('os_version', 'macOS (version unknown)')}
{f"- Additional Info: {ctx['additional_info']}" if ctx.get('additional_info') else ""}

Task: This is an informational finding. Provide context and optional actions.

Since this is inventory data, focus on:
1. Explaining what was inventoried and why it matters
2. Suggesting optional improvements or best practices
3. Providing commands to get more details if useful
4. NOT suggesting fixes (unless there's an actual issue)

Keep the response brief and informative rather than prescriptive.
"""


def get_prompt_for_category(
    category: str, finding: dict[str, Any], context: dict[str, Any] | None = None
) -> str:
    """
    Get the appropriate prompt template for a finding category.

    Args:
        category: Finding category (config, vuln, secrets, network, inventory, other)
        finding: Finding details
        context: Additional context

    Returns:
        Formatted prompt string
    """
    prompt_builders = {
        "config": build_config_prompt,
        "vuln": build_vuln_prompt,
        "secrets": build_secrets_prompt,
        "network": build_network_prompt,
        "inventory": build_inventory_prompt,
    }

    builder = prompt_builders.get(category, build_config_prompt)
    return builder(finding, context)
