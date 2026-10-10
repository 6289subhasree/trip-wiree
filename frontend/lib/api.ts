// The one typed client for the TripWire HTTP API. It mirrors the endpoint tables in README.md
// and ARCHITECTURE.md (sections 10 and 18).
//
// Security contract with tripwire/server.py, which this file must not weaken:
//   - every POST carries `X-TripWire-Client: dashboard` (see POST_HEADERS, used by post() only);
//   - requests are same-origin relative paths, so the browser's Origin matches the Host;
//   - bodies are small JSON objects with only the fields the server accepts.
import { setFirewall, toast } from "./ui";
import type {
  AttackResult,
  ChannelAttack,
  DocScenario,
  FirewallMode,
  ForceAttempt,
  GatewayDecision,
  Profile,
  ReplayResult,
  Report,
  Snapshot,
  StreamName,
  TaskDocument,
  TaskView,
  TimelineEntry,
  ToolCallBody,
  VerifyResult,
  WithState,
  Approval,
  Injected,
} from "./types";

const POST_HEADERS = { "Content-Type": "application/json", "X-TripWire-Client": "dashboard" };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  let data: { error?: string; state?: Snapshot };
  try {
    data = await r.json();
  } catch {
    throw new Error("server returned " + r.status);
  }
  if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
  if (data.state) setFirewall(data.state.firewall.mode);
  return data as T;
}

function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

function post<T>(path: string, body: object = {}): Promise<WithState<T>> {
  return request<WithState<T>>(path, { method: "POST", body: JSON.stringify(body), headers: POST_HEADERS });
}

const task = (id: string) => "/api/tasks/" + encodeURIComponent(id);

export const api = {
  // ---------------------------------------------------------------- read-only
  /** GET /api/state: the full snapshot. */
  async state(): Promise<Snapshot> {
    const st = await get<Snapshot>("/api/state");
    setFirewall(st.firewall.mode);
    return st;
  },
  /** GET /api/health */
  health: () => get<{ ok: boolean; firewall: FirewallMode }>("/api/health"),
  /** GET /api/scenarios: document scenarios and channel attacks. */
  scenarios: () => get<{ document: DocScenario[]; channel: ChannelAttack[] }>("/api/scenarios"),

  // ---------------------------------------------------------------- task mode (README "HTTP API")
  /** POST /api/tasks/start: start a task and issue the manifest. */
  startTask: (body: { scenario: string; goal?: string; instruction?: string }) =>
    post<{ task: TaskView }>("/api/tasks/start", body),
  /** POST /api/tasks/select: make a task the current one. */
  selectTask: (taskId: string) => post("/api/tasks/select", { task_id: taskId }),
  /** GET /api/tasks/{id} */
  task: (id: string) => get<{ task: TaskView }>(task(id)),
  /** GET /api/tasks/{id}/document: documents with tagged spans (canaries masked). */
  taskDocument: (id: string) =>
    get<{ task_id: string; documents: TaskDocument[]; injected: Injected[] }>(task(id) + "/document"),
  /** GET /api/tasks/{id}/timeline: evidence ledger. */
  taskTimeline: (id: string) =>
    get<{ task_id: string; state: string; timeline: TimelineEntry[] }>(task(id) + "/timeline"),
  /** GET /api/tasks/{id}/report: blast-radius report. */
  taskReport: (id: string) => get<{ task_id: string; report: Report }>(task(id) + "/report"),
  /** POST /api/tasks/{id}/agent/run: Agent 1 reads, plans and proposes. */
  runAgent: (id: string) => post<{ decisions: GatewayDecision[]; task: TaskView }>(task(id) + "/agent/run"),
  /** POST /api/gateway/tool-call: one proposal, signed by Agent 1, decided by the gateway. */
  toolCall: (body: ToolCallBody) => post<{ decision: GatewayDecision | null }>("/api/gateway/tool-call", body),
  /** POST /api/tasks/{id}/approval: the operator approves or rejects. */
  decideApproval: (id: string, approvalId: string, decision: "approve" | "reject") =>
    post<{ approval: Approval; task: TaskView }>(task(id) + "/approval", { approval_id: approvalId, decision }),
  /** POST /api/tasks/{id}/inject: judge mode, optionally with a forced tool attempt. */
  inject: (id: string, body: { instruction: string; force?: ForceAttempt }) =>
    post<{ task: TaskView }>(task(id) + "/inject", body),
  /** POST /api/replay: baseline vs protected, in throwaway sessions. */
  replay: (body: { scenario: string; instruction?: string; force?: ForceAttempt }) =>
    post<{ replay: ReplayResult }>("/api/replay", body),

  // ---------------------------------------------------------------- event mode (ARCHITECTURE section 10)
  /** POST /api/stream/step: Agent 1 ingests the next deterministic event. */
  streamStep: (stream: StreamName) =>
    post<{ event: string; step: number; of: number; decision: GatewayDecision | null }>("/api/stream/step", { stream }),
  /** POST /api/stream/reset: rewind streams, score 0. */
  streamReset: () => post("/api/stream/reset"),
  /** POST /api/event: a single event. */
  event: (type: string) => post<{ decision: GatewayDecision | null }>("/api/event", { type }),
  /** POST /api/score: explicit score report. */
  score: (score: number) => post<{ decision: GatewayDecision | null }>("/api/score", { score }),
  /** POST /api/alert: Agent 1 explicitly attempts the protected alert. */
  alert: () => post<{ decision: GatewayDecision | null }>("/api/alert"),
  /** POST /api/threshold */
  threshold: (threshold: number) => post("/api/threshold", { threshold }),
  /** POST /api/firewall: 409 for an illegal transition. */
  firewall: (mode: FirewallMode) => post("/api/firewall", { mode }),
  /** POST /api/recover: 409 on a wrong code or during the cooldown. */
  recover: (code: string) => post("/api/recover", { code }),
  /** POST /api/profile */
  profile: (profile: Profile) => post("/api/profile", { profile }),
  /** POST /api/auto-lockdown */
  autoLockdown: (enabled: boolean, threshold?: number) =>
    post("/api/auto-lockdown", threshold === undefined ? { enabled } : { enabled, threshold }),
  /** POST /api/attack/<id>: run one channel attack synchronously. */
  attack: (id: string) => post<{ results: AttackResult[] }>("/api/attack/" + encodeURIComponent(id)),
  /** POST /api/attack-suite: start the bounded background sequence. */
  attackSuite: (scenarios?: string[]) => post("/api/attack-suite", scenarios ? { scenarios } : {}),
  /** POST /api/attack/stop */
  attackStop: () => post("/api/attack/stop"),
  /** POST /api/audit/verify */
  auditVerify: () => post<{ verify: VerifyResult }>("/api/audit/verify"),
  /** POST /api/audit/tamper */
  auditTamper: () => post<{ tampered_seq: number }>("/api/audit/tamper"),
  /** POST /api/reset: new session; keeps threshold, profile and firewall mode. */
  reset: () => post("/api/reset"),
};

/** Refresh the firewall pill from /api/health; shows SERVER OFFLINE when the server is unreachable. */
export async function health(): Promise<{ ok: boolean; firewall: FirewallMode } | null> {
  try {
    const d = await api.health();
    setFirewall(d.firewall);
    return d;
  } catch {
    setFirewall("OFFLINE");
    return null;
  }
}

let busy = false;
export const isBusy = (): boolean => busy;

/** Run one operator action at a time: toast the result, or the server's error, and return null on failure. */
export async function act<T>(call: () => Promise<T>, okMsg?: string | ((d: T) => string)): Promise<T | null> {
  if (busy) return null;
  busy = true;
  document.body.style.cursor = "progress";
  try {
    const d = await call();
    if (okMsg) toast(typeof okMsg === "function" ? okMsg(d) : okMsg);
    return d;
  } catch (e) {
    toast(e instanceof Error ? e.message : String(e), true);
    return null;
  } finally {
    busy = false;
    document.body.style.cursor = "";
  }
}
