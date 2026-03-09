"""
Network Configuration Scanner

Checks network settings for security issues:
- DNS servers
- HTTP/HTTPS proxies
- Wi-Fi security settings
"""

from __future__ import annotations

import subprocess
from typing import Any

from security_check.db import utc_now_iso
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding

# Known safe DNS providers (not exhaustive)
KNOWN_SAFE_DNS = [
    "1.1.1.1",  # Cloudflare
    "1.0.0.1",  # Cloudflare
    "8.8.8.8",  # Google
    "8.8.4.4",  # Google
    "9.9.9.9",  # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
]


class NetworkConfigScanner(Scanner):
    """
    Scans network configuration for security issues.

    What it checks:
    - DNS servers (flags non-standard ones)
    - HTTP/HTTPS proxies (potential MITM risk)
    - Wi-Fi security (checks for open/weak encryption)

    Severity:
    - "critical" for WEP encryption (broken)
    - "high" for open Wi-Fi networks
    - "medium" for HTTP proxies (MITM risk)
    - "low" for non-standard DNS servers
    - "info" for normal configuration

    Platform: macOS only (uses networksetup and scutil commands)
    """

    id = "macos.network_config"
    name = "Network Configuration Security"
    description = "Checks DNS, proxy, and Wi-Fi security settings."
    category = "config"
    supported_platforms = ["darwin"]
    requires_admin = False

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        findings: list[Any] = []
        artifacts: dict[str, Any] = {}

        # Check DNS servers
        dns_findings, dns_artifacts = self._check_dns_servers(run_id, now)
        findings.extend(dns_findings)
        artifacts.update(dns_artifacts)

        # Check HTTP proxy
        proxy_findings, proxy_artifacts = self._check_http_proxy(run_id, now)
        findings.extend(proxy_findings)
        artifacts.update(proxy_artifacts)

        # Check Wi-Fi security
        wifi_findings, wifi_artifacts = self._check_wifi_security(run_id, now)
        findings.extend(wifi_findings)
        artifacts.update(wifi_artifacts)

        return findings, artifacts

    def _check_dns_servers(self, run_id: str, now: str) -> tuple[list[Any], dict[str, Any]]:
        """Check DNS server configuration."""
        findings = []
        artifacts = {}

        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                output = result.stdout
                artifacts["dns_output"] = output

                # Extract nameserver IPs (simple parsing)
                dns_servers = []
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("nameserver[") and ":" in line:
                        # Format: nameserver[0] : 8.8.8.8
                        parts = line.split(":")
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if ip and ip not in dns_servers:
                                dns_servers.append(ip)

                artifacts["dns_servers"] = dns_servers

                if not dns_servers:
                    findings.append(
                        finding(
                            run_id=run_id,
                            created_at=now,
                            scanner_id=self.id,
                            category="config",
                            severity="info",
                            title="No DNS servers detected",
                            description="Could not detect configured DNS servers.",
                            fingerprint_parts=["network_config", "dns", "none"],
                        )
                    )
                else:
                    # Check for non-standard DNS
                    suspicious_dns = [
                        ip for ip in dns_servers
                        if ip not in KNOWN_SAFE_DNS and not ip.startswith("192.168.") and not ip.startswith("10.")
                    ]

                    if suspicious_dns:
                        findings.append(
                            finding(
                                run_id=run_id,
                                created_at=now,
                                scanner_id=self.id,
                                category="config",
                                severity="low",
                                title="Non-standard DNS servers detected",
                                description=f"Detected DNS servers: {', '.join(suspicious_dns)}. "
                                f"These are not common public DNS providers. "
                                f"Verify this is expected (e.g., ISP DNS, corporate DNS).",
                                remediation="If unexpected:\n"
                                "1. Check System Preferences > Network > Advanced > DNS\n"
                                "2. Consider using trusted DNS providers:\n"
                                "   - Cloudflare: 1.1.1.1, 1.0.0.1\n"
                                "   - Google: 8.8.8.8, 8.8.4.4\n"
                                "   - Quad9: 9.9.9.9",
                                references=["https://www.cloudflare.com/learning/dns/what-is-dns/"],
                                evidence=evidence_dict(dns_servers=suspicious_dns),
                                fingerprint_parts=["network_config", "dns", "suspicious"] + suspicious_dns,
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
                                title="DNS configuration looks OK",
                                description=f"Using DNS servers: {', '.join(dns_servers)}",
                                evidence=evidence_dict(dns_servers=dns_servers),
                                fingerprint_parts=["network_config", "dns", "ok"],
                            )
                        )

        except subprocess.TimeoutExpired:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="other",
                    severity="info",
                    title="DNS check timeout",
                    description="scutil --dns command timed out.",
                    fingerprint_parts=["network_config", "dns", "timeout"],
                )
            )
        except Exception as e:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="other",
                    severity="info",
                    title="Error checking DNS",
                    description=f"Could not check DNS configuration: {str(e)}",
                    evidence=evidence_dict(error=str(e)),
                    fingerprint_parts=["network_config", "dns", "error"],
                )
            )

        return findings, {"dns": artifacts}

    def _check_http_proxy(self, run_id: str, now: str) -> tuple[list[Any], dict[str, Any]]:
        """Check HTTP/HTTPS proxy configuration."""
        findings = []
        artifacts = {}

        try:
            # Get active network interface (usually Wi-Fi or Ethernet)
            interface_result = subprocess.run(
                ["networksetup", "-listnetworkserviceorder"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if interface_result.returncode == 0:
                # Try to extract primary service (simplified - just use "Wi-Fi")
                services = ["Wi-Fi", "Ethernet", "USB Ethernet"]

                for service in services:
                    try:
                        # Check web proxy
                        result = subprocess.run(
                            ["networksetup", "-getwebproxy", service],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )

                        if result.returncode == 0:
                            output = result.stdout
                            artifacts[f"proxy_{service}"] = output

                            # Check if proxy is enabled
                            if "Enabled: Yes" in output:
                                # Extract proxy server
                                proxy_server = "unknown"
                                for line in output.splitlines():
                                    if line.startswith("Server:"):
                                        proxy_server = line.split(":", 1)[1].strip()
                                        break

                                findings.append(
                                    finding(
                                        run_id=run_id,
                                        created_at=now,
                                        scanner_id=self.id,
                                        category="config",
                                        severity="medium",
                                        title=f"HTTP proxy configured on {service}",
                                        description=f"HTTP proxy is enabled: {proxy_server}. "
                                        f"Proxies can intercept and modify your traffic (MITM risk). "
                                        f"Verify this is expected (e.g., corporate proxy).",
                                        remediation="If unexpected:\n"
                                        "1. Go to System Preferences > Network\n"
                                        "2. Select your network > Advanced > Proxies\n"
                                        "3. Uncheck 'Web Proxy (HTTP)'\n"
                                        "4. Click OK and Apply",
                                        references=["https://www.cloudflare.com/learning/security/what-is-a-proxy-server/"],
                                        evidence=evidence_dict(service=service, proxy_server=proxy_server),
                                        fingerprint_parts=["network_config", "proxy", service, proxy_server],
                                    )
                                )

                            break  # Found a valid service, stop checking
                    except:
                        continue  # Service might not exist, try next one

        except Exception as e:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="other",
                    severity="info",
                    title="Error checking proxy",
                    description=f"Could not check proxy configuration: {str(e)}",
                    evidence=evidence_dict(error=str(e)),
                    fingerprint_parts=["network_config", "proxy", "error"],
                )
            )

        return findings, {"proxy": artifacts}

    def _check_wifi_security(self, run_id: str, now: str) -> tuple[list[Any], dict[str, Any]]:
        """Check current Wi-Fi network security."""
        findings = []
        artifacts = {}

        try:
            # Get current Wi-Fi network
            result = subprocess.run(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                output = result.stdout
                artifacts["wifi_info"] = output

                ssid = None
                security = None

                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("SSID:"):
                        ssid = line.split(":", 1)[1].strip()
                    elif line.startswith("link auth:"):
                        security = line.split(":", 1)[1].strip()

                if ssid and security:
                    artifacts["ssid"] = ssid
                    artifacts["security"] = security

                    # Check security level
                    if security.lower() == "none" or security.lower() == "open":
                        findings.append(
                            finding(
                                run_id=run_id,
                                created_at=now,
                                scanner_id=self.id,
                                category="config",
                                severity="high",
                                title=f"Connected to open Wi-Fi network",
                                description=f"Currently connected to '{ssid}' with NO encryption. "
                                f"All traffic can be intercepted by anyone in range.",
                                remediation="1. Disconnect from this network immediately\n"
                                "2. Use a VPN if you must use open Wi-Fi\n"
                                "3. Avoid transmitting sensitive data\n"
                                "4. Prefer encrypted networks (WPA2/WPA3)",
                                references=[
                                    "https://www.cloudflare.com/learning/security/glossary/what-is-mitm-attack/",
                                ],
                                evidence=evidence_dict(ssid=ssid, security=security),
                                fingerprint_parts=["network_config", "wifi", "open", ssid],
                            )
                        )
                    elif "wep" in security.lower():
                        findings.append(
                            finding(
                                run_id=run_id,
                                created_at=now,
                                scanner_id=self.id,
                                category="config",
                                severity="critical",
                                title=f"Connected to WEP-encrypted Wi-Fi",
                                description=f"Network '{ssid}' uses WEP encryption, which is broken and easily cracked. "
                                f"WEP provides no real security.",
                                remediation="1. Disconnect from this network\n"
                                "2. Inform the network administrator to upgrade to WPA2/WPA3\n"
                                "3. Use a VPN if you must use this network",
                                references=["https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy"],
                                evidence=evidence_dict(ssid=ssid, security=security),
                                fingerprint_parts=["network_config", "wifi", "wep", ssid],
                            )
                        )
                    elif "wpa" in security.lower():
                        findings.append(
                            finding(
                                run_id=run_id,
                                created_at=now,
                                scanner_id=self.id,
                                category="config",
                                severity="info",
                                title=f"Wi-Fi security looks OK",
                                description=f"Connected to '{ssid}' with {security} encryption.",
                                evidence=evidence_dict(ssid=ssid, security=security),
                                fingerprint_parts=["network_config", "wifi", "ok"],
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
                            title="Not connected to Wi-Fi",
                            description="No active Wi-Fi connection detected.",
                            fingerprint_parts=["network_config", "wifi", "not_connected"],
                        )
                    )

        except Exception as e:
            findings.append(
                finding(
                    run_id=run_id,
                    created_at=now,
                    scanner_id=self.id,
                    category="other",
                    severity="info",
                    title="Error checking Wi-Fi",
                    description=f"Could not check Wi-Fi configuration: {str(e)}",
                    evidence=evidence_dict(error=str(e)),
                    fingerprint_parts=["network_config", "wifi", "error"],
                )
            )

        return findings, {"wifi": artifacts}
