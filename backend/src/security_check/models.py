from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal["inventory", "vuln", "config", "network", "secrets", "other"]


class ScannerInfo(BaseModel):
    id: str
    name: str
    description: str
    category: Category
    requires_admin: bool = False
    supported_platforms: list[str] = Field(default_factory=list)


class RunCreateRequest(BaseModel):
    scanner_ids: list[str] | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class RunSummary(BaseModel):
    id: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    status: Literal["queued", "running", "completed", "failed"]
    error: str | None = None
    requested_scanners: list[str]
    options: dict[str, Any]
    progress_current: int
    progress_total: int
    current_scanner: str | None = None


class Finding(BaseModel):
    id: str
    run_id: str
    created_at: str
    scanner_id: str
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    fingerprint: str


class RunDetail(BaseModel):
    run: RunSummary
    findings: list[Finding]
    artifacts: dict[str, Any] = Field(default_factory=dict)


class RunDiff(BaseModel):
    base_run_id: str | None
    target_run_id: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]


class MetricsOverview(BaseModel):
    latest_run: RunSummary | None
    latest_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    latest_counts_by_category: dict[str, int] = Field(default_factory=dict)


class MetricsTrendPoint(BaseModel):
    date: str
    severity: Severity
    count: int


class MetricsTrends(BaseModel):
    points: list[MetricsTrendPoint]
