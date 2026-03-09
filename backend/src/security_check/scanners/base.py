from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from security_check.models import Category, Finding, Severity


@dataclass(frozen=True)
class ScanContext:
    run_id: str
    platform: Literal["darwin", "linux", "windows", "unknown"]
    options: dict[str, Any]
    artifacts: dict[str, Any]
    osv_api_base: str = ""
    enable_deep_scans: bool = False

    def set_artifact(self, key: str, value: Any) -> None:
        self.artifacts[key] = value

    def get_artifact(self, key: str, default: Any = None) -> Any:
        return self.artifacts.get(key, default)


def make_fingerprint(scanner_id: str, parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    h.update(scanner_id.encode("utf-8"))
    for part in parts:
        h.update(b"\0")
        h.update(part.encode("utf-8"))
    return h.hexdigest()


def evidence_dict(**kwargs: Any) -> dict[str, Any]:
    return json.loads(json.dumps(kwargs, default=str))


class Scanner:
    id: str
    name: str
    description: str
    category: Category
    requires_admin: bool = False
    supported_platforms: list[str] = ["darwin"]

    def run(self, ctx: ScanContext) -> tuple[list[Finding], dict[str, Any]]:
        raise NotImplementedError


def finding(
    *,
    id: str | None = None,
    run_id: str,
    created_at: str,
    scanner_id: str,
    category: Category,
    severity: Severity,
    title: str,
    description: str,
    remediation: str = "",
    references: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    fingerprint_parts: list[str] | None = None,
) -> Finding:
    references = references or []
    evidence = evidence or {}
    fingerprint_parts = fingerprint_parts or [title]
    fp = make_fingerprint(scanner_id, fingerprint_parts)
    finding_id = id or f"{run_id}:{fp}"
    return Finding(
        id=finding_id,
        run_id=run_id,
        created_at=created_at,
        scanner_id=scanner_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        references=references,
        evidence=evidence,
        fingerprint=fp,
    )
