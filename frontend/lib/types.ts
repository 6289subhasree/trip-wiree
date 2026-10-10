// Shapes of the JSON the TripWire backend returns (tripwire/session.py, tripwire/server.py).
// Only the fields the pages read are spelled out; the backend remains the source of truth.

export type FirewallMode = "NORMAL" | "BLOCKING" | "LOCKDOWN";
export type Outcome = "ACCEPTED" | "REJECTED" | "BLOCKED";
export type ToolDecision = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
export type StreamName = "baseline" | "incident";
export type Profile = "strict" | "baseline";

export interface Firewall {
  mode: FirewallMode;
  reason: string;
  actor: string;
  automatic: boolean;
  since: number;
  recovery_locked_until: number | null;
}

export interface Pressure {
  value: number;
  threshold: number;
  auto_lockdown: boolean;
  last_trigger: unknown;
}

export interface AttackRun {
  running: boolean;
  current: string | null;
  done: number;
  total: number;
  started_at: number | null;
  finished_at: number | null;
  stopped: boolean;
  lockdown_after_s?: number | null;
}

export interface Agents {
  monitor: { id: string; role: string; score: number; incident: string | null; status: string; state: string };
  validator: { id: string; role: string; handled: number; status: string; state: string };
  adversary: { id: string; role: string; registered: boolean; state: string; run: AttackRun };
}

export interface DocScenario {
  id: string;
  title: string;
  kind: "clean" | "attack" | "approval" | string;
  invoice_id: string;
  goal: string;
  summary: string;
  expected: string;
  amount_inr: number;
}

export interface ChannelAttack {
  id: string;
  title: string;
  threat_model: "external" | "mitm" | string;
  description: string;
  expected: string;
}

export interface Source {
  context: string;
  id: string;
  trust: string;
  span: number[] | null;
}

export interface GatewayCheck {
  stage: string;
  ok: boolean;
  detail: string;
}

export interface TimelineEntry {
  seq: number;
  at: number;
  kind: string;
  source: Source | null;
  action: string;
  decision: ToolDecision | string;
  code: string;
  reason: string;
  risk?: string;
  codes?: string[];
  purpose?: string;
  executed?: boolean;
  checks?: GatewayCheck[];
}

export interface DocumentSpan {
  start: number;
  end: number;
  text: string;
  tag: string;
}

export interface TaskDocument {
  doc_id: string;
  role: string;
  context: string;
  trust: string;
  text: string;
  spans: DocumentSpan[];
}

export interface Manifest {
  task_id: string;
  goal: string;
  allowed_tools: string[];
  forbidden_tools: string[];
  allowed_data: string[];
  allowed_destinations: string[];
  payment_limit_inr: number;
  approval_required: string[];
}

export interface Approval {
  id: string;
  task_id: string;
  status: "PENDING" | string;
  tool: string;
  args: Record<string, unknown>;
  justification: { purpose: string; task_link: string } | null;
  evidence: { claim: string; source: Source | null; verified: boolean; authorising: boolean }[];
  affected_data: string[];
  amount_inr: number | null;
  risk: string;
  triggers: string[];
}

export interface ToolCount {
  tool: string;
  count: number;
}

export interface Report {
  task_id: string;
  severity: string;
  attempted_severity: string;
  containment: string;
  requests: number;
  out_of_policy_tools: ToolCount[];
  blocked_tools: (ToolCount | string)[];
  unsafe_executed_tools: ToolCount[];
  violation_codes: Record<string, number>;
  sensitive_records_protected: number;
  sensitive_records_exposed: number;
  canaries_protected: number;
  canaries_exposed: number;
  amount_at_risk_inr: number;
  external_destinations_attempted: string[];
  external_destinations_reached: string[];
  rules: string[];
  summary: string;
}

export interface PaymentDraft {
  draft_id?: string;
  id?: string;
  vendor_name?: string;
  amount_inr: number;
  pay_to_account?: string;
  pay_to_ifsc?: string;
  pay_to_changed?: boolean;
  status?: string;
}

export type Injected = string | { instruction?: string; text?: string };

export interface TaskView {
  task_id: string;
  scenario: string;
  goal: string;
  state: string;
  ran: boolean;
  finished: boolean;
  injected: Injected[];
  manifest: Manifest;
  manifest_hash: string;
  capability: { active: boolean } | null;
  documents: TaskDocument[];
  timeline: TimelineEntry[];
  approvals: Approval[];
  report: Report;
  result: { drafts?: PaymentDraft[] } | null;
  risk: { score: number; threshold: number; alerted: boolean } | null;
}

export interface TaskSummary {
  task_id: string;
  scenario: string;
  state: string;
  goal: string;
  ran: boolean;
}

export interface EmailRecord {
  status?: string;
}

export interface GatewayDecision {
  seq: number;
  at: number;
  outcome: Outcome;
  code: string;
  reason: string;
  sender_id: string;
  receiver_id: string;
  message_type: string;
  would_fail: string | null;
  origin: string | null;
  email: EmailRecord | null;
  action: { email: EmailRecord | null } | null;
}

export interface AttackResult {
  at: number;
  scenario: string;
  outcome: Outcome;
  code: string;
  reason: string;
}

export interface OutboxRecord {
  id: string;
  at: number;
  status: string;
  kind?: string;
  correlation_id?: string;
  to: string[];
  subject: string;
  reason: string;
  code?: string;
}

export interface AuditEntry {
  seq: number;
  ts: number;
  kind: string;
  data: Record<string, unknown>;
  prev: string;
  mac: string;
}

export interface Metrics {
  messages: number;
  accepted: number;
  rejected: number;
  blocked: number;
  attack_attempts: number;
  attack_stopped: number;
  unauthorized_emails: number;
  emails_delivered: number;
  email_denied: number;
  tool_requests: number;
  tool_allowed: number;
  tool_blocked: number;
  tool_pending: number;
}

/** GET /api/state, and the `state` field of every POST response. Never contains keys or the recovery code. */
export interface Snapshot {
  firewall: Firewall;
  profile: Profile;
  threshold: number;
  pressure: Pressure;
  agents: Agents;
  streams: Record<StreamName, { pos: number; events: string[] }>;
  events: Record<string, number>;
  doc_scenarios: DocScenario[];
  tasks: TaskSummary[];
  task: TaskView | null;
  approvals_pending: Approval[];
  tool_executions: Record<string, number>;
  scenarios: ChannelAttack[];
  metrics: Metrics;
  feed: GatewayDecision[];
  attack_log: AttackResult[];
  outbox: OutboxRecord[];
  audit: AuditEntry[];
  audit_head: string;
  audit_count: number;
  codes: Record<string, string>;
}

export interface ReplayResult {
  scenario: DocScenario;
  label: string;
  note: string;
  baseline: TaskView;
  protected: TaskView;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  broken_at: number | null;
  why?: string;
  head?: string;
}

export interface ForceAttempt {
  tool: string;
  destination?: string;
  record?: string;
}

export interface ToolCallBody {
  task_id: string;
  tool: string;
  args: Record<string, unknown>;
  purpose?: string;
  task_link?: string;
  evidence?: unknown[];
  resources_requested?: string[];
  destination?: string;
  risk_level?: string;
}

/** Every POST response carries the full snapshot. */
export type WithState<T = unknown> = T & { state: Snapshot };
