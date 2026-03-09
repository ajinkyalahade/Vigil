from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class OsvVulnerability:
    id: str
    summary: str
    details: str
    aliases: list[str]
    references: list[str]
    severities: list[dict[str, Any]]


def _extract_refs(vuln: dict[str, Any]) -> list[str]:
    refs = []
    for r in vuln.get("references") or []:
        url = (r.get("url") or "").strip()
        if url:
            refs.append(url)
    return refs


async def query_batch(
    *,
    base_url: str,
    items: list[dict[str, Any]],
    timeout_s: int = 30,
) -> list[dict[str, Any]]:
    """
    items: [{"package": {"name": "...", "ecosystem": "PyPI"}, "version": "1.2.3"}, ...]
    """
    url = base_url.rstrip("/") + "/v1/querybatch"
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.post(url, json={"queries": items})
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results") or []
        return results


def query_batch_sync(
    *,
    base_url: str,
    items: list[dict[str, Any]],
    timeout_s: int = 30,
) -> list[dict[str, Any]]:
    url = base_url.rstrip("/") + "/v1/querybatch"
    with httpx.Client(timeout=timeout_s) as client:
        resp = client.post(url, json={"queries": items})
        resp.raise_for_status()
        data = resp.json()
        return data.get("results") or []


def parse_vulns(result: dict[str, Any]) -> list[OsvVulnerability]:
    vulns = []
    for v in result.get("vulns") or []:
        vulns.append(
            OsvVulnerability(
                id=v.get("id") or "",
                summary=v.get("summary") or "",
                details=v.get("details") or "",
                aliases=v.get("aliases") or [],
                references=_extract_refs(v),
                severities=v.get("severity") or [],
            )
        )
    return [v for v in vulns if v.id]
