"""
Resolution service for managing AI-generated resolutions.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import uuid
from typing import Any

from ..db import Database, json_dumps, json_loads, utc_now_iso
from .client import AnthropicClient
from .models import Resolution, ResolutionContext, ResolutionFeedback, ResolutionStep, VerificationStep

logger = logging.getLogger(__name__)


class ResolutionService:
    """
    Service for generating and managing AI resolutions for security findings.

    Handles:
    - Resolution generation via Anthropic API
    - Database persistence
    - Caching by fingerprint
    - User feedback tracking
    """

    def __init__(self, db: Database, client: AnthropicClient, cache_ttl: int = 86400):
        """
        Initialize resolution service.

        Args:
            db: Database connection
            client: Anthropic API client
            cache_ttl: Cache TTL in seconds
        """
        self.db = db
        self.client = client
        self.cache_ttl = cache_ttl

    async def generate_resolution(
        self,
        finding: dict[str, Any],
        context: ResolutionContext | None = None,
        use_cache: bool = True,
    ) -> Resolution:
        """
        Generate or retrieve cached resolution for a finding.

        Args:
            finding: Finding details from database
            context: Additional context for generation
            use_cache: Whether to check cache first

        Returns:
            Resolution object

        Raises:
            ValueError: If finding is invalid or generation fails
        """
        finding_id = finding.get("id")
        finding_fingerprint = finding.get("fingerprint")
        run_id = finding.get("run_id")

        if not finding_id or not finding_fingerprint or not run_id:
            raise ValueError("Finding must have id, fingerprint, and run_id")

        # Check cache if enabled
        if use_cache:
            cached = self._get_cached_resolution(finding_fingerprint)
            if cached:
                logger.info(f"Using cached resolution for fingerprint={finding_fingerprint}")
                return cached

        # Generate new resolution
        logger.info(f"Generating new resolution for finding_id={finding_id}")

        context_dict = context.model_dump() if context else {}

        # Redact sensitive evidence fields before sending to AI
        sanitized_finding = self._sanitize_finding(finding)

        # Call AI
        ai_response, tokens_used, latency_ms = await self.client.generate_resolution(
            sanitized_finding, context_dict
        )

        # Create Resolution object
        resolution_id = f"res_{uuid.uuid4().hex[:12]}"
        resolution = Resolution(
            resolution_id=resolution_id,
            finding_id=finding_id,
            finding_fingerprint=finding_fingerprint,
            generated_at=utc_now_iso(),
            analysis=ai_response.analysis,
            steps=ai_response.steps,
            safety_notes=ai_response.safety_notes,
            verification=ai_response.verification,
            references=ai_response.references,
            confidence=ai_response.confidence,
            model_used=self.client.model,
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            status="pending",
        )

        # Store in database
        self._store_resolution(resolution, run_id)

        return resolution

    def get_resolution(self, resolution_id: str) -> Resolution | None:
        """
        Retrieve a resolution by ID.

        Args:
            resolution_id: Resolution identifier

        Returns:
            Resolution object or None if not found
        """
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM finding_resolutions
                WHERE id = ?
                """,
                (resolution_id,),
            ).fetchone()

            if not row:
                return None

            return self._resolution_from_row(row)

    def get_resolutions_for_finding(self, finding_fingerprint: str) -> list[Resolution]:
        """
        Get all resolutions for a finding fingerprint (across runs).

        Args:
            finding_fingerprint: Finding fingerprint

        Returns:
            List of resolutions, newest first
        """
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM finding_resolutions
                WHERE finding_fingerprint = ?
                ORDER BY generated_at DESC
                """,
                (finding_fingerprint,),
            ).fetchall()

            return [self._resolution_from_row(row) for row in rows]

    def submit_feedback(
        self, resolution_id: str, feedback: ResolutionFeedback
    ) -> Resolution | None:
        """
        Submit user feedback for a resolution.

        Args:
            resolution_id: Resolution identifier
            feedback: User feedback

        Returns:
            Updated resolution or None if not found
        """
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE finding_resolutions
                SET user_feedback = ?,
                    feedback_notes = ?
                WHERE id = ?
                """,
                (feedback.feedback, feedback.notes, resolution_id),
            )

            if conn.total_changes == 0:
                return None

        return self.get_resolution(resolution_id)

    def mark_applied(self, resolution_id: str) -> Resolution | None:
        """
        Mark a resolution as applied by the user.

        Args:
            resolution_id: Resolution identifier

        Returns:
            Updated resolution or None if not found
        """
        with self.db.connect() as conn:
            conn.execute(
                """
                UPDATE finding_resolutions
                SET status = 'applied',
                    applied_at = ?
                WHERE id = ?
                """,
                (utc_now_iso(), resolution_id),
            )

            if conn.total_changes == 0:
                return None

        return self.get_resolution(resolution_id)

    def _sanitize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Remove or redact sensitive data from finding before sending to AI.

        Args:
            finding: Original finding

        Returns:
            Sanitized finding dict
        """
        sanitized = finding.copy()
        evidence = sanitized.get("evidence", {})

        # Redact fields that might contain actual secret values
        sensitive_fields = [
            "value",
            "content",
            "secret",
            "password",
            "token",
            "key",
            "credential",
        ]

        for field in sensitive_fields:
            if field in evidence:
                evidence[field] = "***REDACTED***"

        sanitized["evidence"] = evidence
        return sanitized

    def _get_cached_resolution(self, fingerprint: str) -> Resolution | None:
        """
        Get cached resolution for a fingerprint if within TTL.

        Args:
            fingerprint: Finding fingerprint

        Returns:
            Resolution object or None if not cached or expired
        """
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM finding_resolutions
                WHERE finding_fingerprint = ?
                AND datetime(generated_at) > datetime('now', '-' || ? || ' seconds')
                ORDER BY generated_at DESC
                LIMIT 1
                """,
                (fingerprint, self.cache_ttl),
            ).fetchone()

            if not row:
                return None

            return self._resolution_from_row(row)

    def _store_resolution(self, resolution: Resolution, run_id: str) -> None:
        """
        Store resolution in database.

        Args:
            resolution: Resolution to store
            run_id: Run ID this resolution belongs to
        """
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO finding_resolutions (
                    id, finding_fingerprint, run_id, finding_id, generated_at,
                    analysis, steps_json, safety_notes_json, verification_json,
                    references_json, confidence, status, user_feedback, feedback_notes,
                    applied_at, model_used, tokens_used, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resolution.resolution_id,
                    resolution.finding_fingerprint,
                    run_id,
                    resolution.finding_id,
                    resolution.generated_at,
                    resolution.analysis,
                    json_dumps([step.model_dump() for step in resolution.steps]),
                    json_dumps(resolution.safety_notes),
                    json_dumps(resolution.verification.model_dump())
                    if resolution.verification
                    else json_dumps(None),
                    json_dumps(resolution.references),
                    resolution.confidence,
                    resolution.status,
                    resolution.user_feedback,
                    resolution.feedback_notes,
                    resolution.applied_at,
                    resolution.model_used,
                    resolution.tokens_used,
                    resolution.latency_ms,
                ),
            )

    def _resolution_from_row(self, row: sqlite3.Row) -> Resolution:
        """
        Convert database row to Resolution object.

        Args:
            row: SQLite row

        Returns:
            Resolution object
        """
        verification_data = json_loads(row["verification_json"])

        return Resolution(
            resolution_id=row["id"],
            finding_id=row["finding_id"],
            finding_fingerprint=row["finding_fingerprint"],
            generated_at=row["generated_at"],
            analysis=row["analysis"],
            steps=[ResolutionStep(**s) for s in json_loads(row["steps_json"])],
            safety_notes=json_loads(row["safety_notes_json"]),
            verification=VerificationStep(**verification_data) if verification_data else None,
            references=json_loads(row["references_json"]),
            confidence=row["confidence"],
            model_used=row["model_used"],
            tokens_used=row["tokens_used"],
            latency_ms=row["latency_ms"],
            status=row["status"],
            user_feedback=row["user_feedback"],
            feedback_notes=row["feedback_notes"],
            applied_at=row["applied_at"],
        )
