"""
ExecutionService — runs AI-generated resolution steps on the local machine,
streams real-time output via SSE, and tracks session state in the DB.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any, AsyncGenerator

from security_check.ai_resolution.models import ExecutionSession, ResolutionStep, StepState
from security_check.config import Settings
from security_check.db import Database, json_dumps, json_loads, utc_now_iso

# Commands blocked unconditionally regardless of what the AI generates.
_BLOCKED_PATTERNS = [
    r"rm\s+-[rRfF]*[rR][fF]?\s+/(?!tmp/|var/folders/)",  # rm -rf / (allow /tmp)
    r"dd\s+if=",
    r"\bmkfs\b",
    r">\s*/etc/passwd",
    r">\s*/etc/shadow",
    r":\(\)\s*\{",  # fork bomb
    r"chmod\s+-R\s+[0-7]*7[0-7]*\s+/\s*$",
    r"sudo\s+rm\s+-rf\s+/\s*$",
]
_BLOCKED_RE = [re.compile(p) for p in _BLOCKED_PATTERNS]


def _is_blocked(command: str) -> bool:
    return any(r.search(command) for r in _BLOCKED_RE)


def _sse(event_type: str, data: Any) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


class ExecutionService:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        # Per-session SSE queues: session_id -> asyncio.Queue[dict | None]
        self._queues: dict[str, asyncio.Queue[dict[str, Any] | None]] = {}
        # Keep task references to prevent GC
        self._tasks: set[asyncio.Task[None]] = set()

    # ── Session CRUD ──────────────────────────────────────────────────────────

    def create_session(
        self,
        resolution_id: str,
        finding_id: str,
        run_id: str,
        steps: list[ResolutionStep],
    ) -> ExecutionSession:
        session_id = str(uuid.uuid4())
        now = utc_now_iso()
        initial_steps = [StepState(order=s.order) for s in steps]
        with self.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO execution_sessions
                    (id, resolution_id, finding_id, run_id, created_at, status,
                     current_step, steps_state)
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    session_id,
                    resolution_id,
                    finding_id,
                    run_id,
                    now,
                    steps[0].order if steps else 0,
                    json_dumps([s.model_dump() for s in initial_steps]),
                ),
            )
        return self._load(session_id)

    def get_session(self, session_id: str) -> ExecutionSession | None:
        try:
            return self._load(session_id)
        except KeyError:
            return None

    def _load(self, session_id: str) -> ExecutionSession:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM execution_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if not row:
            raise KeyError(session_id)
        d = dict(row)
        return ExecutionSession(
            session_id=d["id"],
            resolution_id=d["resolution_id"],
            finding_id=d["finding_id"],
            run_id=d["run_id"],
            created_at=d["created_at"],
            status=d["status"],
            current_step=d["current_step"],
            steps=[StepState(**s) for s in json_loads(d["steps_state"])],
            abort_reason=d.get("abort_reason"),
        )

    def _save(
        self,
        session_id: str,
        steps: list[StepState],
        status: str | None = None,
        current_step: int | None = None,
    ) -> None:
        parts: list[Any] = [json_dumps([s.model_dump() for s in steps])]
        sql = "UPDATE execution_sessions SET steps_state = ?"
        if status is not None:
            sql += ", status = ?"
            parts.append(status)
        if current_step is not None:
            sql += ", current_step = ?"
            parts.append(current_step)
        sql += " WHERE id = ?"
        parts.append(session_id)
        with self.db.connect() as conn:
            conn.execute(sql, parts)

    # ── Step actions ──────────────────────────────────────────────────────────

    async def approve_step(
        self,
        session_id: str,
        step_order: int,
        resolution_steps: list[ResolutionStep],
        confirmed_risk: bool = False,
    ) -> ExecutionSession:
        session = self._load(session_id)

        if session.status in ("aborted", "completed", "failed"):
            raise ValueError(f"Session is {session.status}")

        step_state = next((s for s in session.steps if s.order == step_order), None)
        if not step_state:
            raise KeyError(f"Step {step_order} not found in session")
        if step_state.status not in ("pending",):
            raise ValueError(f"Step {step_order} is already {step_state.status}")

        res_step = next((s for s in resolution_steps if s.order == step_order), None)
        if not res_step:
            raise KeyError(f"Resolution step {step_order} not found")
        if not res_step.command:
            raise ValueError(f"Step {step_order} has no command")

        if not res_step.is_safe and not confirmed_risk:
            raise PermissionError(
                "Step is marked unsafe — set confirmed_risk=true to proceed"
            )
        if _is_blocked(res_step.command):
            raise PermissionError(f"Command blocked by safety policy")

        # Mark approved
        step_state.status = "approved"
        step_state.approved_at = utc_now_iso()
        self._save(session_id, session.steps, status="running", current_step=step_order)

        # Background execution
        task = asyncio.create_task(
            self._run_step(
                session_id,
                step_order,
                res_step.command,
                res_step.expected_output,
                max(s.order for s in resolution_steps),
            )
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return self._load(session_id)

    async def skip_step(self, session_id: str, step_order: int) -> ExecutionSession:
        session = self._load(session_id)
        if session.status in ("aborted", "completed"):
            raise ValueError(f"Session is {session.status}")

        step_state = next((s for s in session.steps if s.order == step_order), None)
        if not step_state:
            raise KeyError(f"Step {step_order} not found")

        step_state.status = "skipped"
        step_state.completed_at = utc_now_iso()

        max_order = max(s.order for s in session.steps)
        next_step = step_order + 1
        if next_step > max_order:
            self._save(session_id, session.steps, status="completed", current_step=step_order)
        else:
            self._save(session_id, session.steps, status="pending", current_step=next_step)

        updated = self._load(session_id)
        await self._emit(session_id, "session_state", updated.model_dump())
        return updated

    async def abort_session(self, session_id: str, reason: str | None = None) -> ExecutionSession:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE execution_sessions SET status = 'aborted', abort_reason = ? WHERE id = ?",
                (reason, session_id),
            )
        updated = self._load(session_id)
        await self._emit(session_id, "session_state", updated.model_dump())
        await self._emit(session_id, "session_aborted", {"reason": reason})
        await self._close_queue(session_id)
        return updated

    # ── SSE streaming ─────────────────────────────────────────────────────────

    def _get_or_create_queue(self, session_id: str) -> asyncio.Queue[dict[str, Any] | None]:
        if session_id not in self._queues:
            self._queues[session_id] = asyncio.Queue()
        return self._queues[session_id]

    async def _emit(self, session_id: str, event_type: str, data: Any) -> None:
        queue = self._queues.get(session_id)
        if queue:
            await queue.put({"type": event_type, "data": data})

    async def _close_queue(self, session_id: str) -> None:
        queue = self._queues.get(session_id)
        if queue:
            await queue.put(None)

    async def stream_session(self, session_id: str) -> AsyncGenerator[str, None]:
        """Async generator yielding SSE-formatted strings."""
        session = self.get_session(session_id)
        if session:
            yield _sse("session_state", session.model_dump())

        queue = self._get_or_create_queue(session_id)
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield _sse(event["type"], event["data"])
        except GeneratorExit:
            pass

    # ── Internal step runner ──────────────────────────────────────────────────

    async def _run_step(
        self,
        session_id: str,
        step_order: int,
        command: str,
        expected_output: str | None,
        max_step_order: int,
    ) -> None:
        try:
            await self._execute(
                session_id, step_order, command, expected_output, max_step_order
            )
        except Exception as exc:
            # Unexpected internal error — mark step failed
            session = self._load(session_id)
            step_state = next(
                (s for s in session.steps if s.order == step_order), None
            )
            if step_state:
                step_state.status = "failed"
                step_state.completed_at = utc_now_iso()
                step_state.output = f"[Internal error: {exc}]"
                self._save(session_id, session.steps, status="paused", current_step=step_order)
            updated = self._load(session_id)
            await self._emit(session_id, "step_failed", {"step": step_order, "error": str(exc)})
            await self._emit(session_id, "session_state", updated.model_dump())
            await self._emit(
                session_id,
                "session_paused",
                {"session_id": session_id, "current_step": step_order, "reason": "internal_error"},
            )

    async def _execute(
        self,
        session_id: str,
        step_order: int,
        command: str,
        expected_output: str | None,
        max_step_order: int,
    ) -> None:
        # Mark step as running
        session = self._load(session_id)
        step_state = next(s for s in session.steps if s.order == step_order)
        step_state.status = "running"
        step_state.started_at = utc_now_iso()
        self._save(session_id, session.steps)

        output_chunks: list[str] = []
        exit_code: int = -1
        proc: asyncio.subprocess.Process | None = None

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None

            async def _read() -> None:
                async for raw in proc.stdout:  # type: ignore[union-attr]
                    line = raw.decode("utf-8", errors="replace")
                    output_chunks.append(line)
                    await self._emit(
                        session_id, "output", {"step": step_order, "chunk": line}
                    )

            await asyncio.wait_for(
                asyncio.gather(_read(), proc.wait()),
                timeout=self.settings.execution_step_timeout_seconds,
            )
            exit_code = proc.returncode or 0

        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                proc.kill()
            msg = f"\n[Timed out after {self.settings.execution_step_timeout_seconds}s]\n"
            output_chunks.append(msg)
            await self._emit(session_id, "output", {"step": step_order, "chunk": msg})
            exit_code = -1

        full_output = "".join(output_chunks)

        # Unix convention:
        #   0        = success
        #   1        = "no results" / condition not met (ls, grep, find) — treat as soft warning
        #   2+       = real error — hard fail, pause session for user review
        # output_matched is informational only; AI expected_output is a human description.
        step_hard_failed = exit_code >= 2 or exit_code < 0
        step_soft_warned = exit_code == 1

        # Persist final step state
        session = self._load(session_id)
        step_state = next(s for s in session.steps if s.order == step_order)
        step_state.status = "failed" if step_hard_failed else "completed"
        step_state.completed_at = utc_now_iso()
        step_state.exit_code = exit_code
        step_state.output = full_output[-4000:]

        if step_hard_failed:
            self._save(session_id, session.steps, status="paused", current_step=step_order)
            updated = self._load(session_id)
            await self._emit(
                session_id,
                "step_failed",
                {
                    "step": step_order,
                    "exit_code": exit_code,
                    "output": full_output[-1000:],
                },
            )
            await self._emit(session_id, "session_state", updated.model_dump())
            await self._emit(
                session_id,
                "session_paused",
                {"session_id": session_id, "current_step": step_order, "reason": "step_failed"},
            )
        else:
            # Success (exit 0) or soft warning (exit 1) — both advance
            next_step = step_order + 1
            if next_step > max_step_order:
                new_status = "completed"
                self._save(session_id, session.steps, status=new_status, current_step=step_order)
            else:
                self._save(session_id, session.steps, status="pending", current_step=next_step)

            updated = self._load(session_id)

            if step_soft_warned:
                # Notify UI so it can show a dismissible warning banner
                await self._emit(
                    session_id,
                    "step_warning",
                    {
                        "step": step_order,
                        "exit_code": exit_code,
                        "output": full_output[-1000:],
                        "note": (
                            "Exit code 1 usually means 'no results found' for commands like "
                            "ls, grep, and find — not necessarily an error. "
                            "The step has been marked complete and execution continues."
                        ),
                    },
                )

            await self._emit(
                session_id,
                "step_complete",
                {"step": step_order, "exit_code": exit_code},
            )
            await self._emit(session_id, "session_state", updated.model_dump())

            if next_step > max_step_order:
                await self._emit(session_id, "session_complete", {"session_id": session_id})
                await self._close_queue(session_id)
