export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Category = "inventory" | "vuln" | "config" | "network" | "secrets" | "other";

export type ScannerInfo = {
  id: string;
  name: string;
  description: string;
  category: Category;
  requires_admin: boolean;
  supported_platforms: string[];
};

export type RunSummary = {
  id: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  status: "queued" | "running" | "completed" | "failed";
  error: string | null;
  requested_scanners: string[];
  options: Record<string, unknown>;
  progress_current: number;
  progress_total: number;
  current_scanner: string | null;
};

export type Finding = {
  id: string;
  run_id: string;
  created_at: string;
  scanner_id: string;
  category: Category;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  references: string[];
  fingerprint: string;
};

export type RunDetail = {
  run: RunSummary;
  findings: Finding[];
  artifacts: Record<string, unknown>;
};

export type RunDiff = {
  base_run_id: string | null;
  target_run_id: string;
  new_findings: Finding[];
  resolved_findings: Finding[];
};

export type MetricsOverview = {
  latest_run: RunSummary | null;
  latest_counts_by_severity: Record<string, number>;
  latest_counts_by_category: Record<string, number>;
};

export type MetricsTrendPoint = {
  date: string;
  severity: Severity;
  count: number;
};

export type MetricsTrends = {
  points: MetricsTrendPoint[];
};

// AI Resolution types

export type ResolutionStep = {
  order: number;
  description: string;
  command: string | null;
  expected_output: string | null;
  is_safe: boolean;
  requires_confirmation: boolean;
};

export type VerificationStep = {
  command: string;
  expected_output: string;
};

export type ResolutionContext = {
  os_version?: string;
  username?: string;
  additional_info?: string;
};

export type Resolution = {
  resolution_id: string;
  finding_id: string;
  finding_fingerprint: string;
  generated_at: string;
  analysis: string;
  steps: ResolutionStep[];
  safety_notes: string[];
  verification: VerificationStep | null;
  references: string[];
  confidence: "low" | "medium" | "high";
  model_used: string;
  tokens_used: number | null;
  latency_ms: number | null;
  status: "pending" | "accepted" | "rejected" | "applied" | "failed";
  user_feedback: "helpful" | "not_helpful" | "partially_helpful" | null;
  feedback_notes: string | null;
  applied_at: string | null;
};

export type ResolutionFeedback = {
  feedback: "helpful" | "not_helpful" | "partially_helpful";
  notes?: string;
};

// Agent execution types

export type StepStatus = "pending" | "approved" | "running" | "completed" | "failed" | "skipped";
export type SessionStatus = "pending" | "running" | "paused" | "completed" | "aborted" | "failed";

export type StepState = {
  order: number;
  status: StepStatus;
  approved_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  exit_code: number | null;
  output: string;
  output_matched: boolean | null;
};

export type ExecutionSession = {
  session_id: string;
  resolution_id: string;
  finding_id: string;
  run_id: string;
  created_at: string;
  status: SessionStatus;
  current_step: number;
  steps: StepState[];
  abort_reason: string | null;
};
