from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from security_check.ai_resolution import (
    ApproveStepRequest,
    ExecutionService,
    ExecutionSession,
    Resolution,
    ResolutionContext,
    ResolutionFeedback,
    ResolutionService,
)
from security_check.ai_resolution.models import ResolutionStep
from security_check.config import Settings, get_settings
from security_check.db import json_loads
from security_check.metrics import counts_for_run, severity_trends
from security_check.models import (
    MetricsOverview,
    MetricsTrendPoint,
    MetricsTrends,
    RunCreateRequest,
    RunDiff,
    RunDetail,
    RunSummary,
    ScannerInfo,
)
from security_check.runner import ScanService, select_default_scanners


security = HTTPBearer(auto_error=False)


def require_token(
    request: Request,
    settings: Settings = Depends(get_settings),
    creds: HTTPAuthorizationCredentials | None = Depends(security),
) -> None:
    if not settings.api_token:
        return
    bearer = (creds.credentials if creds else "").strip()
    # EventSource can't set headers, so also accept ?token= query param
    query_token = request.query_params.get("token", "").strip()
    if bearer != settings.api_token and query_token != settings.api_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


def get_service(request: Request) -> ScanService:
    return request.app.state.scan_service  # type: ignore[no-any-return]


def get_resolution_service(request: Request) -> ResolutionService:
    service = request.app.state.resolution_service
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="AI resolution service not available. Check ANTHROPIC_API_KEY configuration.",
        )
    return service  # type: ignore[no-any-return]


def get_execution_service(request: Request, settings: Settings = Depends(get_settings)) -> ExecutionService:
    if not settings.execution_enabled:
        raise HTTPException(status_code=503, detail="Agent execution is disabled (SC_EXECUTION_ENABLED=false)")
    return request.app.state.execution_service  # type: ignore[no-any-return]


router = APIRouter(prefix="/api", dependencies=[Depends(require_token)])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/scanners", response_model=list[ScannerInfo])
def list_scanners(service: ScanService = Depends(get_service)) -> list[ScannerInfo]:
    return service.list_scanners()


@router.post("/runs", response_model=RunSummary)
def create_run(
    body: RunCreateRequest,
    bg: BackgroundTasks,
    service: ScanService = Depends(get_service),
) -> RunSummary:
    scanner_ids = body.scanner_ids or select_default_scanners(service.registry)
    # Validate
    unknown = [s for s in scanner_ids if service.registry.get(s) is None]
    if unknown:
        raise HTTPException(status_code=400, detail={"unknown_scanners": unknown})

    run = service.create_run(scanner_ids=scanner_ids, options=body.options)
    bg.add_task(service.run_scan, run.id)
    return run


@router.get("/runs", response_model=list[RunSummary])
def list_runs(service: ScanService = Depends(get_service), limit: int = 50) -> list[RunSummary]:
    return service.list_runs(limit=limit)


@router.get("/runs/{run_id}", response_model=RunDetail)
def get_run(run_id: str, service: ScanService = Depends(get_service)) -> RunDetail:
    try:
        run = service.get_run(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Run not found")
    findings = service.get_findings(run_id)
    artifacts = service.get_artifacts(run_id)
    return RunDetail(run=run, findings=findings, artifacts=artifacts)


@router.get("/runs/{run_id}/diff", response_model=RunDiff)
def diff_run(
    run_id: str,
    service: ScanService = Depends(get_service),
    against: str = "previous",
) -> RunDiff:
    try:
        _ = service.get_run(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Run not found")

    if against == "previous":
        base_id = service.find_previous_completed_run_id(run_id)
        if not base_id:
            return RunDiff(
                base_run_id=None,
                target_run_id=run_id,
                new_findings=[],
                resolved_findings=[],
            )
    else:
        base_id = against
        try:
            _ = service.get_run(base_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Base run not found")

    new_findings, resolved_findings = service.diff_runs(base_id, run_id)
    return RunDiff(
        base_run_id=base_id,
        target_run_id=run_id,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
    )


@router.get("/metrics/overview", response_model=MetricsOverview)
def metrics_overview(service: ScanService = Depends(get_service)) -> MetricsOverview:
    runs = service.list_runs(limit=1)
    if not runs:
        return MetricsOverview(latest_run=None)
    latest = runs[0]
    by_sev, by_cat = counts_for_run(service.db, latest.id)
    return MetricsOverview(
        latest_run=latest,
        latest_counts_by_severity=by_sev,
        latest_counts_by_category=by_cat,
    )


@router.get("/metrics/trends", response_model=MetricsTrends)
def metrics_trends(service: ScanService = Depends(get_service), days: int = 30) -> MetricsTrends:
    points = [
        MetricsTrendPoint(date=p["date"], severity=p["severity"], count=p["count"])
        for p in severity_trends(service.db, days=days)
    ]
    return MetricsTrends(points=points)


# AI Resolution endpoints


@router.post("/findings/{finding_id}/resolve", response_model=Resolution)
async def generate_resolution(
    finding_id: str,
    context: ResolutionContext | None = None,
    scan_service: ScanService = Depends(get_service),
    resolution_service: ResolutionService = Depends(get_resolution_service),
) -> Resolution:
    """
    Generate an AI-powered resolution for a security finding.

    Args:
        finding_id: Finding ID to resolve
        context: Optional context (os_version, username, etc.)
        scan_service: Scan service dependency
        resolution_service: Resolution service dependency

    Returns:
        Generated resolution with steps

    Raises:
        404: Finding not found
        503: AI service not available
    """
    # Get the finding from database
    with scan_service.db.connect() as conn:
        row = conn.execute(
            """
            SELECT f.*, r.id as run_id
            FROM scan_findings f
            JOIN scan_runs r ON f.run_id = r.id
            WHERE f.id = ?
            """,
            (finding_id,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Finding not found")

        # Convert to dict
        finding = dict(row)

    # Generate resolution
    try:
        resolution = await resolution_service.generate_resolution(finding, context)
        return resolution
    except Exception as e:
        import logging
        logging.error(f"Failed to generate resolution: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate resolution: {str(e)}"
        )


@router.get("/resolutions/{resolution_id}", response_model=Resolution)
def get_resolution(
    resolution_id: str,
    resolution_service: ResolutionService = Depends(get_resolution_service),
) -> Resolution:
    """Get a resolution by ID."""
    resolution = resolution_service.get_resolution(resolution_id)
    if not resolution:
        raise HTTPException(status_code=404, detail="Resolution not found")
    return resolution


@router.get("/resolutions/history/{fingerprint}", response_model=list[Resolution])
def get_resolution_history(
    fingerprint: str,
    resolution_service: ResolutionService = Depends(get_resolution_service),
) -> list[Resolution]:
    """Get resolution history for a finding fingerprint."""
    return resolution_service.get_resolutions_for_finding(fingerprint)


@router.post("/resolutions/{resolution_id}/feedback")
def submit_resolution_feedback(
    resolution_id: str,
    feedback: ResolutionFeedback,
    resolution_service: ResolutionService = Depends(get_resolution_service),
) -> Resolution:
    """Submit feedback for a resolution."""
    resolution = resolution_service.submit_feedback(resolution_id, feedback)
    if not resolution:
        raise HTTPException(status_code=404, detail="Resolution not found")
    return resolution


@router.post("/resolutions/{resolution_id}/mark-applied")
def mark_resolution_applied(
    resolution_id: str,
    resolution_service: ResolutionService = Depends(get_resolution_service),
) -> Resolution:
    """Mark a resolution as applied by the user."""
    resolution = resolution_service.mark_applied(resolution_id)
    if not resolution:
        raise HTTPException(status_code=404, detail="Resolution not found")
    return resolution


# Agent execution endpoints


@router.post("/resolutions/{resolution_id}/sessions", response_model=ExecutionSession)
def create_execution_session(
    resolution_id: str,
    scan_service: ScanService = Depends(get_service),
    execution_service: ExecutionService = Depends(get_execution_service),
) -> ExecutionSession:
    """Create a new agent execution session for an existing resolution."""
    with scan_service.db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM finding_resolutions WHERE id = ?", (resolution_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Resolution not found")

    row = dict(row)
    steps = [ResolutionStep(**s) for s in json_loads(row["steps_json"])]
    if not steps:
        raise HTTPException(status_code=422, detail="Resolution has no executable steps")

    return execution_service.create_session(
        resolution_id=resolution_id,
        finding_id=row["finding_id"],
        run_id=row["run_id"],
        steps=steps,
    )


@router.get("/sessions/{session_id}", response_model=ExecutionSession)
def get_execution_session(
    session_id: str,
    execution_service: ExecutionService = Depends(get_execution_service),
) -> ExecutionSession:
    """Get the current state of an execution session."""
    session = execution_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/sessions/{session_id}/steps/{step_order}/approve", response_model=ExecutionSession)
async def approve_step(
    session_id: str,
    step_order: int,
    body: ApproveStepRequest,
    scan_service: ScanService = Depends(get_service),
    execution_service: ExecutionService = Depends(get_execution_service),
) -> ExecutionSession:
    """Approve and execute a resolution step."""
    session = execution_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    with scan_service.db.connect() as conn:
        row = conn.execute(
            "SELECT steps_json FROM finding_resolutions WHERE id = ?",
            (session.resolution_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Resolution not found")

    resolution_steps = [ResolutionStep(**s) for s in json_loads(row["steps_json"])]

    try:
        return await execution_service.approve_step(
            session_id, step_order, resolution_steps, body.confirmed_risk
        )
    except PermissionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/sessions/{session_id}/steps/{step_order}/skip", response_model=ExecutionSession)
async def skip_step(
    session_id: str,
    step_order: int,
    execution_service: ExecutionService = Depends(get_execution_service),
) -> ExecutionSession:
    """Skip a step and advance to the next one."""
    try:
        return await execution_service.skip_step(session_id, step_order)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/sessions/{session_id}/abort", response_model=ExecutionSession)
async def abort_session(
    session_id: str,
    execution_service: ExecutionService = Depends(get_execution_service),
) -> ExecutionSession:
    """Abort an execution session."""
    session = execution_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return await execution_service.abort_session(session_id, reason="user_aborted")


@router.get("/sessions/{session_id}/stream")
async def stream_session(
    session_id: str,
    execution_service: ExecutionService = Depends(get_execution_service),
) -> StreamingResponse:
    """SSE stream for real-time step output. Auth handled by require_token (supports ?token=)."""
    session = execution_service.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return StreamingResponse(
        execution_service.stream_session(session_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
