"""
Integration tests for AI resolution API endpoints.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from security_check.ai_resolution import AnthropicClient, ResolutionService
from security_check.ai_resolution.models import ResolutionResponse, ResolutionStep, VerificationStep
from security_check.app import create_app
from security_check.config import Settings


def test_resolution_endpoint_without_api_key(tmp_path):
    """Should return 503 when AI service is not configured."""
    app = create_app(Settings(db_path=tmp_path / "test.db", anthropic_api_key=None))
    client = TestClient(app)

    # Try to generate resolution
    resp = client.post("/api/findings/test-finding-id/resolve")

    assert resp.status_code == 503
    assert "not available" in resp.json()["detail"].lower()


def test_resolution_endpoint_with_invalid_finding(tmp_path):
    """Should return 404 when finding doesn't exist."""
    # Create app with mock AI service
    app = create_app(Settings(db_path=tmp_path / "test.db", anthropic_api_key="sk-test"))
    client = TestClient(app)

    resp = client.post("/api/findings/nonexistent-finding/resolve")

    assert resp.status_code == 404
    assert "Finding not found" in resp.json()["detail"]


def test_resolution_endpoint_success(tmp_path):
    """Should generate resolution for valid finding."""
    # Create app and setup database
    app = create_app(Settings(db_path=tmp_path / "test.db", anthropic_api_key="sk-test"))
    client = TestClient(app)

    # Create a test run and finding
    scan_service = app.state.scan_service
    run = scan_service.create_run(scanner_ids=["macos.hardening"], options={})

    # Insert a test finding directly
    with scan_service.db.connect() as conn:
        finding_id = f"{run.id}:test-fingerprint"
        conn.execute(
            """
            INSERT INTO scan_findings (
                id, run_id, created_at, scanner_id, category, severity,
                title, description, evidence_json, remediation, references_json, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                run.id,
                "2026-02-04T10:00:00Z",
                "macos.ssh_permissions",
                "config",
                "high",
                "SSH key world-readable",
                "Private key has incorrect permissions",
                json.dumps({"path": "~/.ssh/id_rsa", "permissions": "-rw-r--r--"}),
                "Run: chmod 600 ~/.ssh/id_rsa",
                json.dumps([]),
                "test-fingerprint",
            ),
        )

    # Mock the AI client's generate_resolution method
    mock_resolution = ResolutionResponse(
        analysis="The SSH key has incorrect permissions",
        steps=[
            ResolutionStep(
                order=1,
                description="Check current permissions",
                command="ls -la ~/.ssh/id_rsa",
                expected_output="-rw-r--r--",
                is_safe=True,
                requires_confirmation=False,
            ),
            ResolutionStep(
                order=2,
                description="Fix permissions",
                command="chmod 600 ~/.ssh/id_rsa",
                expected_output="",
                is_safe=True,
                requires_confirmation=True,
            ),
        ],
        safety_notes=["This modifies file permissions"],
        verification=VerificationStep(
            command="ls -la ~/.ssh/id_rsa",
            expected_output="-rw-------",
        ),
        references=["https://www.ssh.com/academy/ssh/config"],
        confidence="high",
    )

    # Patch the generate_resolution method
    with patch.object(
        AnthropicClient,
        "generate_resolution",
        new=AsyncMock(return_value=(mock_resolution, 300, 1500)),
    ):
        resp = client.post(f"/api/findings/{finding_id}/resolve")

    assert resp.status_code == 200
    data = resp.json()

    assert data["analysis"] == "The SSH key has incorrect permissions"
    assert len(data["steps"]) == 2
    assert data["steps"][0]["command"] == "ls -la ~/.ssh/id_rsa"
    assert data["confidence"] == "high"
    assert data["finding_id"] == finding_id
    assert data["model_used"] == "claude-sonnet-4.5-20250929"
    assert data["tokens_used"] == 300


def test_get_resolution_by_id(tmp_path):
    """Should retrieve resolution by ID."""
    app = create_app(Settings(db_path=tmp_path / "test.db", anthropic_api_key="sk-test"))
    client = TestClient(app)

    # Create test data
    scan_service = app.state.scan_service
    run = scan_service.create_run(scanner_ids=["macos.hardening"], options={})

    with scan_service.db.connect() as conn:
        finding_id = f"{run.id}:test-fp"
        conn.execute(
            """
            INSERT INTO scan_findings (
                id, run_id, created_at, scanner_id, category, severity,
                title, description, evidence_json, remediation, references_json, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                run.id,
                "2026-02-04T10:00:00Z",
                "test.scanner",
                "config",
                "high",
                "Test finding",
                "Test description",
                json.dumps({}),
                "Test remediation",
                json.dumps([]),
                "test-fp",
            ),
        )

        # Insert resolution directly
        resolution_id = "res_test123"
        conn.execute(
            """
            INSERT INTO finding_resolutions (
                id, finding_fingerprint, run_id, finding_id, generated_at,
                analysis, steps_json, safety_notes_json, verification_json,
                references_json, confidence, status, model_used, tokens_used, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution_id,
                "test-fp",
                run.id,
                finding_id,
                "2026-02-04T10:00:00Z",
                "Test analysis",
                json.dumps([{"order": 1, "description": "Test step", "is_safe": True}]),
                json.dumps(["Safety note"]),
                json.dumps(None),
                json.dumps([]),
                "high",
                "pending",
                "claude-sonnet-4.5-20250929",
                100,
                500,
            ),
        )

    resp = client.get(f"/api/resolutions/{resolution_id}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["resolution_id"] == resolution_id
    assert data["analysis"] == "Test analysis"


def test_submit_feedback(tmp_path):
    """Should submit feedback for resolution."""
    app = create_app(Settings(db_path=tmp_path / "test.db", anthropic_api_key="sk-test"))
    client = TestClient(app)

    # Create test resolution
    scan_service = app.state.scan_service
    run = scan_service.create_run(scanner_ids=["macos.hardening"], options={})

    with scan_service.db.connect() as conn:
        finding_id = f"{run.id}:test-fp"
        conn.execute(
            """
            INSERT INTO scan_findings (
                id, run_id, created_at, scanner_id, category, severity,
                title, description, evidence_json, remediation, references_json, fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                run.id,
                "2026-02-04T10:00:00Z",
                "test.scanner",
                "config",
                "high",
                "Test",
                "Test",
                json.dumps({}),
                "Test",
                json.dumps([]),
                "test-fp",
            ),
        )

        resolution_id = "res_feedback123"
        conn.execute(
            """
            INSERT INTO finding_resolutions (
                id, finding_fingerprint, run_id, finding_id, generated_at,
                analysis, steps_json, safety_notes_json, verification_json,
                references_json, confidence, status, model_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution_id,
                "test-fp",
                run.id,
                finding_id,
                "2026-02-04T10:00:00Z",
                "Test",
                json.dumps([]),
                json.dumps([]),
                json.dumps(None),
                json.dumps([]),
                "high",
                "pending",
                "claude-sonnet-4.5-20250929",
            ),
        )

    # Submit feedback
    resp = client.post(
        f"/api/resolutions/{resolution_id}/feedback",
        json={"feedback": "helpful", "notes": "Great suggestion!"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["user_feedback"] == "helpful"
    assert data["feedback_notes"] == "Great suggestion!"
