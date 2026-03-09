from __future__ import annotations

from typing import Any

from security_check.db import utc_now_iso
from security_check.osv import parse_vulns, query_batch_sync
from security_check.scanners.base import ScanContext, Scanner, evidence_dict, finding


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _best_cvss(vuln_severities: list[dict[str, Any]]) -> float | None:
    best: float | None = None
    for s in vuln_severities:
        score_str = s.get("score")
        if not score_str:
            continue
        try:
            score = float(score_str)
        except (TypeError, ValueError):
            continue
        if best is None or score > best:
            best = score
    return best


class OsvPackageVulnScanner(Scanner):
    id = "pkg.osv.vulns"
    name = "OSV Package Vulnerabilities"
    description = "Queries osv.dev for known vulnerabilities in inventoried packages."
    category = "vuln"
    supported_platforms = ["darwin", "linux", "windows"]

    def run(self, ctx: ScanContext) -> tuple[list[Any], dict[str, Any]]:
        now = utc_now_iso()
        run_id = ctx.run_id

        base = (ctx.osv_api_base or "").strip()
        if not base:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="vuln",
                        severity="info",
                        title="OSV scanning disabled",
                        description="Set SC_OSV_API_BASE to enable OSV queries.",
                        fingerprint_parts=["osv", "disabled"],
                    )
                ],
                {},
            )

        packages: list[dict[str, Any]] = []
        for key in ("packages.pypi", "packages.npm"):
            pkgs = ctx.get_artifact(key, [])
            if isinstance(pkgs, list):
                packages.extend(pkgs)

        if not packages:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="vuln",
                        severity="info",
                        title="No packages available for OSV query",
                        description="Run inventory scanners first (pip/npm) to collect packages for vulnerability checks.",
                        fingerprint_parts=["osv", "no_packages"],
                    )
                ],
                {},
            )

        # Avoid huge payloads; keep first N packages.
        max_pkgs = int(ctx.options.get("osv_max_packages", 400))
        truncated = packages[:max_pkgs]

        queries = []
        for p in truncated:
            name = (p.get("name") or "").strip()
            version = (p.get("version") or "").strip()
            ecosystem = (p.get("ecosystem") or "").strip()
            if not name or not version or not ecosystem:
                continue
            queries.append({"package": {"name": name, "ecosystem": ecosystem}, "version": version})

        if not queries:
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="vuln",
                        severity="info",
                        title="No valid packages for OSV query",
                        description="Inventoried packages were missing required fields (name/version/ecosystem).",
                        fingerprint_parts=["osv", "no_valid_packages"],
                    )
                ],
                {},
            )

        try:
            batch_size = int(ctx.options.get("osv_batch_size", 100))
            if batch_size <= 0:
                batch_size = 100
            results: list[dict[str, Any]] = []
            for start in range(0, len(queries), batch_size):
                chunk = queries[start : start + batch_size]
                results.extend(query_batch_sync(base_url=base, items=chunk, timeout_s=30))
        except Exception as e:  # noqa: BLE001
            return (
                [
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="vuln",
                        severity="info",
                        title="OSV query failed",
                        description="Could not query OSV API (network unavailable or blocked).",
                        evidence=evidence_dict(error=str(e)),
                        fingerprint_parts=["osv", "error", str(e)],
                    )
                ],
                {},
            )

        findings: list[Any] = []
        vuln_count = 0
        for q, r in zip(queries, results):
            pkg = q.get("package") or {}
            name = pkg.get("name") or ""
            ecosystem = pkg.get("ecosystem") or ""
            version = q.get("version") or ""
            vulns = parse_vulns(r or {})
            for v in vulns:
                vuln_count += 1
                score = _best_cvss(v.severities)
                severity = _severity_from_cvss(score)
                refs = list(dict.fromkeys(v.references + [f"{base.rstrip('/')}/vulnerability/{v.id}"]))
                findings.append(
                    finding(
                        run_id=run_id,
                        created_at=now,
                        scanner_id=self.id,
                        category="vuln",
                        severity=severity,  # type: ignore[arg-type]
                        title=f"{ecosystem} {name}@{version}: {v.id}",
                        description=v.summary or "Known vulnerability reported by OSV.",
                        remediation=f"Update {name} to a fixed version (ecosystem: {ecosystem}).",
                        references=refs[:10],
                        evidence=evidence_dict(
                            package={"ecosystem": ecosystem, "name": name, "version": version},
                            aliases=v.aliases,
                            cvss_best=score,
                        ),
                        fingerprint_parts=["osv", ecosystem, name, version, v.id],
                    )
                )

        summary = {
            "packages_queried": len(queries),
            "packages_total": len(packages),
            "packages_truncated": len(packages) - len(truncated),
            "vulns_found": vuln_count,
            "batch_size": int(ctx.options.get("osv_batch_size", 100)),
        }
        findings.append(
            finding(
                run_id=run_id,
                created_at=now,
                scanner_id=self.id,
                category="vuln",
                severity="info",
                title="OSV vulnerability query complete",
                description=(
                    f"Queried {summary['packages_queried']} packages; found {summary['vulns_found']} vulnerabilities."
                ),
                evidence=evidence_dict(summary=summary),
                fingerprint_parts=["osv", "summary"],
            )
        )

        return findings, {"osv.summary": summary}
