import { useEffect, useRef, useState } from "react";
import {
  apiAbortSession,
  apiApproveStep,
  apiCreateSession,
  apiSkipStep,
  openSessionStream,
} from "../api/client";
import type { ExecutionSession, Resolution, ResolutionStep, StepState } from "../types";

interface Props {
  resolution: Resolution;
  findingTitle: string;
  onClose: () => void;
}

// ── Step status dot ──────────────────────────────────────────────────────────

function StepDot({ state, isCurrent }: { state: StepState; isCurrent: boolean }) {
  // Amber for completed-with-warning (exit code 1)
  const isWarn = state.status === "completed" && state.exit_code === 1;

  const bg = isWarn
    ? "var(--warn, #f59e0b)"
    : {
        pending: "var(--muted, #888)",
        approved: "var(--info, #3b82f6)",
        running: "var(--info, #3b82f6)",
        completed: "var(--good, #22c55e)",
        failed: "var(--bad, #ef4444)",
        skipped: "var(--warn, #f59e0b)",
      }[state.status] ?? "var(--muted)";

  const symbol =
    state.status === "running"
      ? "⟳"
      : state.status === "completed"
        ? isWarn ? "~" : "✓"
        : state.status === "failed"
          ? "✕"
          : state.status === "skipped"
            ? "⤳"
            : state.order;

  return (
    <div
      title={`Step ${state.order}: ${state.status}${state.exit_code != null ? ` (exit ${state.exit_code})` : ""}`}
      style={{
        width: 28,
        height: 28,
        borderRadius: "50%",
        background: bg,
        border: isCurrent ? "2px solid white" : "2px solid transparent",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 11,
        fontWeight: 700,
        color: "white",
        flexShrink: 0,
        transition: "background 0.2s",
      }}
    >
      {symbol}
    </div>
  );
}

// ── Inline terminal (compact, used inside cards) ──────────────────────────────

function InlineTerminal({ output, maxHeight = 200 }: { output: string; maxHeight?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [output]);
  if (!output) return null;
  return (
    <div
      ref={ref}
      style={{
        background: "#0d1117",
        color: "#c9d1d9",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas",
        fontSize: 12,
        padding: 10,
        borderRadius: 6,
        maxHeight,
        overflowY: "auto",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
        marginTop: 10,
        border: "1px solid #30363d",
      }}
    >
      {output}
    </div>
  );
}

// ── Step warning banner (exit code 1) ────────────────────────────────────────

function StepWarningBanner({
  warning,
  onDismiss,
}: {
  warning: { step: number; exit_code: number; output: string; note: string };
  onDismiss: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      className="card"
      style={{
        padding: 12,
        marginBottom: 16,
        background: "var(--bg-warn, #1c1407)",
        border: "1px solid var(--warn, #f59e0b)",
      }}
    >
      <div style={{ display: "flex", alignItems: "start", gap: 10 }}>
        <span style={{ fontSize: 16, flexShrink: 0 }}>⚠</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: "var(--warn, #f59e0b)" }}>
            Step {warning.step} exited with code 1
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>
            {warning.note}
          </div>
          {warning.output && (
            <button
              className="btn secondary"
              onClick={() => setExpanded((v) => !v)}
              style={{ fontSize: 11, padding: "2px 8px", marginTop: 8 }}
            >
              {expanded ? "Hide output" : "Show output"}
            </button>
          )}
          {expanded && warning.output && (
            <InlineTerminal output={warning.output} maxHeight={160} />
          )}
        </div>
        <button
          onClick={onDismiss}
          style={{
            background: "none",
            border: "none",
            color: "var(--muted)",
            cursor: "pointer",
            fontSize: 16,
            lineHeight: 1,
            padding: 2,
            flexShrink: 0,
          }}
        >
          ×
        </button>
      </div>
    </div>
  );
}

// ── Current step card ────────────────────────────────────────────────────────

function CurrentStepCard({
  stepState,
  resStep,
  isRunning,
  liveOutput,
  confirmedRisk,
  onConfirmRisk,
  onApprove,
  onSkip,
  loading,
}: {
  stepState: StepState;
  resStep: ResolutionStep | undefined;
  isRunning: boolean;
  liveOutput: string;
  confirmedRisk: boolean;
  onConfirmRisk: (v: boolean) => void;
  onApprove: () => void;
  onSkip: () => void;
  loading: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const isPending = stepState.status === "pending";
  const isFailed = stepState.status === "failed";
  const isUnsafe = resStep && !resStep.is_safe;
  const approveDisabled = loading || isRunning || (isUnsafe && !confirmedRisk);

  // Show the captured output inline for failed steps so users don't have to scroll
  const outputToShow = isFailed ? (stepState.output || "") : liveOutput;

  return (
    <div
      className="card"
      style={{
        padding: 16,
        background: isFailed
          ? "var(--bg-bad, #450a0a)"
          : isUnsafe
            ? "var(--bg-warn, #1c1407)"
            : undefined,
        border: isFailed ? "1px solid var(--bad, #ef4444)" : undefined,
      }}
    >
      {/* Step header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: "50%",
            background: isFailed ? "var(--bad)" : isUnsafe ? "var(--warn)" : "var(--info)",
            color: "white",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontWeight: 700,
            fontSize: 14,
            flexShrink: 0,
          }}
        >
          {stepState.order}
        </div>
        <div style={{ fontWeight: 700, fontSize: 15, flex: 1 }}>
          {resStep?.description ?? `Step ${stepState.order}`}
        </div>
        {isUnsafe && (
          <span className="badge high" style={{ fontSize: 11 }}>
            ⚠ Unsafe
          </span>
        )}
      </div>

      {/* Command */}
      {resStep?.command && (
        <div style={{ marginBottom: 12 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              background: "var(--bg-secondary)",
              borderRadius: 6,
              padding: "8px 12px",
            }}
          >
            <code
              style={{
                flex: 1,
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas",
                fontSize: 13,
                overflowX: "auto",
                whiteSpace: "pre",
              }}
            >
              {resStep.command}
            </code>
            <button
              className="btn secondary"
              onClick={() => {
                navigator.clipboard.writeText(resStep.command!);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              style={{ fontSize: 11, padding: "3px 8px", flexShrink: 0 }}
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          {resStep.expected_output && (
            <div className="muted" style={{ marginTop: 4, fontSize: 12 }}>
              Expected: <code>{resStep.expected_output}</code>
            </div>
          )}
        </div>
      )}

      {/* Failure explanation — inline with output */}
      {isFailed && (
        <>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 8,
              color: "var(--bad, #ef4444)",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <span>✕</span>
            <span>
              Exit code {stepState.exit_code ?? "?"} — command returned an error.
              Review the output, then retry or continue anyway.
            </span>
          </div>
          {outputToShow && <InlineTerminal output={outputToShow} maxHeight={220} />}
        </>
      )}

      {/* Unsafe confirmation checkbox */}
      {isUnsafe && isPending && (
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 12,
            marginTop: 4,
            fontSize: 13,
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={confirmedRisk}
            onChange={(e) => onConfirmRisk(e.target.checked)}
          />
          I understand this step carries elevated risk and want to proceed
        </label>
      )}

      {/* Action buttons */}
      {(isPending || isFailed) && (
        <div style={{ display: "flex", gap: 8, marginTop: isFailed ? 12 : 0 }}>
          <button
            className="btn"
            onClick={onApprove}
            disabled={approveDisabled}
            style={{ fontSize: 13 }}
          >
            {isRunning ? "Running…" : isFailed ? "Retry step" : "▶ Approve & Run"}
          </button>
          <button
            className="btn secondary"
            onClick={onSkip}
            disabled={loading || isRunning}
            style={{ fontSize: 13 }}
          >
            {isFailed ? "Continue anyway" : "Skip"}
          </button>
        </div>
      )}

      {/* Live streaming indicator + output */}
      {isRunning && !isFailed && (
        <>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>
            Running…
          </div>
          {liveOutput && <InlineTerminal output={liveOutput} maxHeight={220} />}
        </>
      )}
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

type StepWarning = { step: number; exit_code: number; output: string; note: string };

export default function ExecutionSessionPanel({ resolution, findingTitle, onClose }: Props) {
  const [session, setSession] = useState<ExecutionSession | null>(null);
  const [liveOutput, setLiveOutput] = useState("");
  const [confirmedRisk, setConfirmedRisk] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(true);
  const [stepWarning, setStepWarning] = useState<StepWarning | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    let mounted = true;

    setCreating(true);
    apiCreateSession(resolution.resolution_id)
      .then((sess) => {
        if (!mounted) return;
        setSession(sess);
        setCreating(false);

        const es = openSessionStream(sess.session_id);
        esRef.current = es;

        es.addEventListener("session_state", (e: MessageEvent) => {
          if (!mounted) return;
          const updated: ExecutionSession = JSON.parse(e.data);
          setSession((prev) => {
            // Clear live output when the current step advances
            if (prev && updated.current_step !== prev.current_step) setLiveOutput("");
            return updated;
          });
          setConfirmedRisk(false);
        });

        es.addEventListener("output", (e: MessageEvent) => {
          if (!mounted) return;
          const { chunk } = JSON.parse(e.data) as { chunk: string };
          setLiveOutput((prev) => prev + chunk);
        });

        es.addEventListener("step_warning", (e: MessageEvent) => {
          if (!mounted) return;
          setStepWarning(JSON.parse(e.data) as StepWarning);
        });

        es.addEventListener("step_complete", () => {
          if (!mounted) return;
          setLoading(false);
        });

        es.addEventListener("step_failed", () => {
          if (!mounted) return;
          setLoading(false);
        });

        es.addEventListener("session_complete", () => {
          if (!mounted) return;
          setLoading(false);
          es.close();
        });

        es.addEventListener("session_aborted", () => {
          if (!mounted) return;
          setLoading(false);
          es.close();
        });

        es.onerror = () => {
          // EventSource retries automatically
        };
      })
      .catch((e) => {
        if (!mounted) return;
        setError(e instanceof Error ? e.message : String(e));
        setCreating(false);
      });

    return () => {
      mounted = false;
      esRef.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resolution.resolution_id]);

  const currentStepState = session?.steps.find((s) => s.order === session.current_step) ?? null;
  const currentResStep = resolution.steps.find((s) => s.order === session?.current_step);
  const isRunning =
    currentStepState?.status === "running" || currentStepState?.status === "approved";
  const isDone = session?.status === "completed" || session?.status === "aborted";

  const handleApprove = async () => {
    if (!session || !currentStepState) return;
    setLoading(true);
    setError(null);
    setLiveOutput("");
    setStepWarning(null);
    try {
      await apiApproveStep(session.session_id, currentStepState.order, confirmedRisk);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setLoading(false);
    }
  };

  const handleSkip = async () => {
    if (!session || !currentStepState) return;
    setLoading(true);
    setStepWarning(null);
    try {
      const updated = await apiSkipStep(session.session_id, currentStepState.order);
      setSession(updated);
      setLiveOutput("");
      setConfirmedRisk(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleAbort = async () => {
    if (!session) return;
    if (!window.confirm("Abort this session? Steps already run will not be undone.")) return;
    try {
      const updated = await apiAbortSession(session.session_id);
      setSession(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const maxStep = session ? Math.max(...session.steps.map((s) => s.order)) : 0;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1100,
        padding: 20,
      }}
      onClick={isDone ? onClose : undefined}
    >
      <div
        className="card"
        style={{ maxWidth: 760, width: "100%", maxHeight: "92vh", overflow: "auto", padding: 24 }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "start",
            marginBottom: 20,
          }}
        >
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Agent Execution</h2>
            <div className="muted" style={{ marginTop: 4, fontSize: 13 }}>
              {findingTitle}
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {session && !isDone && (
              <button
                className="btn secondary"
                onClick={handleAbort}
                style={{ fontSize: 13, color: "var(--bad)" }}
              >
                Abort
              </button>
            )}
            <button
              className="btn secondary"
              onClick={onClose}
              style={{ fontSize: 20, padding: "2px 10px" }}
            >
              ×
            </button>
          </div>
        </div>

        {creating && (
          <div className="muted" style={{ textAlign: "center", padding: 40 }}>
            Creating session…
          </div>
        )}

        {error && (
          <div className="badge high" style={{ marginBottom: 16, display: "block" }}>
            {error}
          </div>
        )}

        {session && (
          <>
            {/* Progress strip */}
            <div
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                marginBottom: 20,
                flexWrap: "wrap",
              }}
            >
              {session.steps.map((s, i) => (
                <div key={s.order} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <StepDot state={s} isCurrent={s.order === session.current_step} />
                  {i < session.steps.length - 1 && (
                    <div
                      style={{
                        height: 2,
                        width: 20,
                        background:
                          s.status === "completed"
                            ? s.exit_code === 1
                              ? "var(--warn, #f59e0b)"
                              : "var(--good)"
                            : "var(--border, #333)",
                      }}
                    />
                  )}
                </div>
              ))}
              <div className="muted" style={{ marginLeft: 8, fontSize: 12 }}>
                {session.status === "completed"
                  ? "All steps completed"
                  : session.status === "aborted"
                    ? "Aborted"
                    : `Step ${session.current_step} of ${maxStep}`}
              </div>
            </div>

            {/* Soft warning banner from previous step (exit code 1) */}
            {stepWarning && (
              <StepWarningBanner
                warning={stepWarning}
                onDismiss={() => setStepWarning(null)}
              />
            )}

            {/* Completed state */}
            {session.status === "completed" && (
              <div
                className="card"
                style={{ background: "var(--bg-good, #052e16)", padding: 20, textAlign: "center" }}
              >
                <div style={{ fontSize: 32, marginBottom: 8 }}>✓</div>
                <div style={{ fontWeight: 700, fontSize: 16 }}>All steps completed</div>
                {resolution.verification && (
                  <div style={{ marginTop: 16, textAlign: "left" }}>
                    <div className="muted" style={{ marginBottom: 6, fontSize: 13 }}>
                      Run this command to verify the fix is active:
                    </div>
                    <code
                      style={{
                        display: "block",
                        background: "var(--bg-secondary)",
                        padding: "8px 12px",
                        borderRadius: 4,
                        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas",
                        fontSize: 13,
                      }}
                    >
                      {resolution.verification.command}
                    </code>
                    <div className="muted" style={{ marginTop: 4, fontSize: 12 }}>
                      Expected: <code>{resolution.verification.expected_output}</code>
                    </div>
                  </div>
                )}
                <button className="btn" onClick={onClose} style={{ marginTop: 20 }}>
                  Done
                </button>
              </div>
            )}

            {/* Aborted state */}
            {session.status === "aborted" && (
              <div
                className="card"
                style={{ background: "var(--bg-bad, #450a0a)", padding: 20, textAlign: "center" }}
              >
                <div style={{ fontSize: 32, marginBottom: 8 }}>✕</div>
                <div style={{ fontWeight: 700 }}>Session aborted</div>
                <div className="muted" style={{ marginTop: 8, fontSize: 13 }}>
                  Steps already completed will not be undone automatically.
                </div>
                <button className="btn secondary" onClick={onClose} style={{ marginTop: 16 }}>
                  Close
                </button>
              </div>
            )}

            {/* Active step — output is now inline inside the card */}
            {!isDone && currentStepState && (
              <CurrentStepCard
                stepState={currentStepState}
                resStep={currentResStep}
                isRunning={isRunning}
                liveOutput={liveOutput}
                confirmedRisk={confirmedRisk}
                onConfirmRisk={setConfirmedRisk}
                onApprove={handleApprove}
                onSkip={handleSkip}
                loading={loading}
              />
            )}

            {/* Completed steps summary */}
            {session.steps.some((s) =>
              ["completed", "failed", "skipped"].includes(s.status),
            ) && (
              <div style={{ marginTop: 20 }}>
                <div style={{ fontWeight: 700, marginBottom: 8, fontSize: 13 }}>
                  Completed steps
                </div>
                {session.steps
                  .filter((s) => ["completed", "failed", "skipped"].includes(s.status))
                  .map((s) => {
                    const resS = resolution.steps.find((r) => r.order === s.order);
                    const isWarnStep = s.status === "completed" && s.exit_code === 1;
                    return (
                      <div
                        key={s.order}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          padding: "6px 0",
                          borderBottom: "1px solid var(--border, #333)",
                          fontSize: 13,
                        }}
                      >
                        <StepDot state={s} isCurrent={false} />
                        <span style={{ flex: 1 }}>
                          {resS?.description ?? `Step ${s.order}`}
                        </span>
                        <span
                          className="muted"
                          style={{
                            fontSize: 11,
                            color: isWarnStep ? "var(--warn)" : undefined,
                          }}
                        >
                          {s.status}
                          {s.exit_code != null ? ` (exit ${s.exit_code})` : ""}
                        </span>
                      </div>
                    );
                  })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
