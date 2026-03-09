"""
AI-powered resolution generation for security findings.

This module provides intelligent remediation suggestions using Anthropic's Claude API.
"""

from .models import (
    Resolution,
    ResolutionStep,
    ResolutionContext,
    ResolutionFeedback,
    StepState,
    ExecutionSession,
    ApproveStepRequest,
)
from .service import ResolutionService
from .client import AnthropicClient
from .executor import ExecutionService

__all__ = [
    "Resolution",
    "ResolutionStep",
    "ResolutionContext",
    "ResolutionFeedback",
    "StepState",
    "ExecutionSession",
    "ApproveStepRequest",
    "ResolutionService",
    "AnthropicClient",
    "ExecutionService",
]
