"""
Data models for AI resolution feature.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ResolutionStep(BaseModel):
    """A single step in the resolution process."""

    order: int = Field(description="Step number in sequence")
    description: str = Field(description="What this step does")
    command: str | None = Field(default=None, description="Command to execute")
    expected_output: str | None = Field(default=None, description="Expected result")
    is_safe: bool = Field(default=True, description="Whether this step is safe to execute")
    requires_confirmation: bool = Field(
        default=False, description="Whether user confirmation is needed"
    )


class VerificationStep(BaseModel):
    """Verification step to confirm fix was successful."""

    command: str = Field(description="Command to verify the fix")
    expected_output: str = Field(description="What the output should show")


class ResolutionContext(BaseModel):
    """Additional context for generating resolutions."""

    os_version: str | None = None
    username: str | None = None
    additional_info: str | None = None


class Resolution(BaseModel):
    """Complete AI-generated resolution for a finding."""

    resolution_id: str = Field(description="Unique resolution identifier")
    finding_id: str = Field(description="Finding this resolves")
    finding_fingerprint: str = Field(description="Fingerprint for cross-run tracking")
    generated_at: str = Field(description="ISO timestamp when generated")

    # AI-generated content
    analysis: str = Field(description="Root cause analysis")
    steps: list[ResolutionStep] = Field(description="Step-by-step remediation")
    safety_notes: list[str] = Field(default_factory=list, description="Safety warnings")
    verification: VerificationStep | None = Field(default=None, description="How to verify")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    confidence: Literal["low", "medium", "high"] = Field(
        description="AI confidence in this resolution"
    )

    # Metadata
    model_used: str = Field(description="AI model identifier")
    tokens_used: int | None = Field(default=None, description="Tokens consumed")
    latency_ms: int | None = Field(default=None, description="Generation time")

    # User interaction
    status: Literal["pending", "accepted", "rejected", "applied", "failed"] = Field(
        default="pending"
    )
    user_feedback: Literal["helpful", "not_helpful", "partially_helpful"] | None = None
    feedback_notes: str | None = None
    applied_at: str | None = None


class ResolutionFeedback(BaseModel):
    """User feedback on a resolution."""

    feedback: Literal["helpful", "not_helpful", "partially_helpful"]
    notes: str | None = None


class ResolutionResponse(BaseModel):
    """
    Structured response from AI for resolution generation.
    This matches the JSON format we request from Claude.
    """

    analysis: str
    steps: list[ResolutionStep]
    safety_notes: list[str] = Field(default_factory=list)
    verification: VerificationStep | None = None
    references: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "medium"


class ResolutionRequest(BaseModel):
    """Request to generate a resolution."""

    finding_id: str
    context: ResolutionContext | None = None


# ── Agent execution models ────────────────────────────────────────────────────


class StepState(BaseModel):
    """Runtime state of a single execution step."""

    order: int
    status: Literal["pending", "approved", "running", "completed", "failed", "skipped"] = "pending"
    approved_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    exit_code: int | None = None
    output: str = ""
    output_matched: bool | None = None


class ExecutionSession(BaseModel):
    """An active agent execution session for a resolution."""

    session_id: str
    resolution_id: str
    finding_id: str
    run_id: str
    created_at: str
    status: Literal["pending", "running", "paused", "completed", "aborted", "failed"] = "pending"
    current_step: int = 0
    steps: list[StepState] = Field(default_factory=list)
    abort_reason: str | None = None


class ApproveStepRequest(BaseModel):
    """Request to approve and execute a resolution step."""

    confirmed_risk: bool = Field(
        default=False,
        description="Must be True for steps where is_safe=False",
    )
