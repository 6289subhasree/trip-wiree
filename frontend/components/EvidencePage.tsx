"use client";
// Evidence page, ported from tripwire/web/evidence.html: audit chain (verify / simulate
// tampering), task reports, outbox, audit log and the meaning of every refusal code.
import { useEffect, useState } from "react";
import { act, api, health, isBusy } from "@/lib/api";
import { fmtINR, pretty, time } from "@/lib/format";
import { toast } from "@/lib/ui";
import type { AuditEntry, Report, Snapshot, VerifyResult } from "@/lib/types";

function Stat({ label, value, note, cls }: { label: string; value: number; note: string; cls?: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className={"statbig " + (cls || "")}>{String(value)}</div>
      <div className="muted">{note}</div>
    </div>
  );
}

function auditLine(e: AuditEntry): string {
  const d = e.data || {};
  if (e.kind === "gateway.decision") return d.type + " · " + d.sender + " → " + d.outcome + " " + d.code;
  if (e.kind === "firewall.transition") return d.from_mode + " → " + d.to_mode + " · " + d.reason;
  if (e.kind === "email.delivered") return ((d.to as string[] | undefined) || []).join(", ") + " [simulated]";
  return JSON.stringify(d).slice(0, 90);
}

function ReportCards({ sel, r }: { sel: string; r: Report }) {
  return (
    <>
      <div className="card pad">
        <div className="label">{"Blast radius · " + sel}</div>
        <div className="statbig" style={{ marginTop: 14, color: r.severity === "Low" ? "var(--mint)" : "var(--red)" }}>{r.severity}</div>
        <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>{r.containment + " · attempted " + r.attempted_severity}</div>
        <p className="soft" style={{ fontSize: 14 }}>{r.summary}</p>
        <dl className="kv">
          <dt>Requests</dt><dd>{r.requests}</dd>
          <dt>Blocked tools</dt><dd>{(r.blocked_tools || []).map((x) => (typeof x === "string" ? x : x.tool)).join(", ") || "none"}</dd>
          <dt>Records protected / exposed</dt><dd>{r.sensitive_records_protected + " / " + r.sensitive_records_exposed}</dd>
          <dt>Canaries protected / exposed</dt><dd>{r.canaries_protected + " / " + r.canaries_exposed}</dd>
          <dt>Amount at risk</dt><dd>{fmtINR(r.amount_at_risk_inr)}</dd>
          <dt>External destinations tried</dt><dd>{(r.external_destinations_attempted || []).join(", ") || "none"}</dd>
        </dl>
      </div>
      <div className="card pad">
        <div className="label">How severity is scored</div>
        <div className="list" style={{ marginTop: 10 }}>
          {(r.rules || []).map((x) => <div className="li" key={x}><span className="red">•</span><span>{x}</span></div>)}
        </div>
        <div className="label" style={{ marginTop: 18 }}>Violations</div>
        <div className="pillrow" style={{ marginTop: 10 }}>
          {Object.entries(r.violation_codes || {}).map(([k, v]) => <span className="chip no" key={k}><i />{k + " × " + v}</span>)}
        </div>
      </div>
    </>
  );
}

export function EvidencePage() {
  const [S, setS] = useState<Snapshot | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
  // `verdict` drives the red block in the chain and is cleared by a new tamper; `shown` is the
  // sentence under the chain, which (as in the original page) stays until the next verify.
  const [verdict, setVerdict] = useState<VerifyResult | null>(null);
  const [shown, setShown] = useState<VerifyResult | null>(null);
  const [report, setReport] = useState<{ sel: string; r: Report } | { sel: string; error: string } | null>(null);

  useEffect(() => {
    api.state().then(setS).catch((e: Error) => toast("Cannot reach the TripWire server: " + e.message, true));
    const timer = setInterval(() => { if (!isBusy() && !document.hidden) health(); }, 3000);
    return () => clearInterval(timer);
  }, []);

  const tasks = (S && S.tasks) || [];
  const sel = picked || (tasks.length ? tasks[tasks.length - 1].task_id : null);

  // The blast radius is recomputed from lineage on every request, so refetch whenever the snapshot changes.
  useEffect(() => {
    if (!sel) { setReport(null); return; }
    let live = true;
    api.taskReport(sel)
      .then((d) => { if (live) setReport({ sel, r: d.report }); })
      .catch((e: Error) => { if (live) setReport({ sel, error: e.message }); });
    return () => { live = false; };
  }, [sel, S]);

  async function verify() {
    const d = await act(() => api.auditVerify(), (x) => x.verify.ok ? "Chain intact: " + x.verify.checked + " entries verified" : "Tampering detected at entry #" + x.verify.broken_at);
    if (!d) return;
    setVerdict(d.verify); setShown(d.verify); setS(d.state);
  }
  async function tamper() {
    const d = await act(() => api.auditTamper(), (x) => "An intruder edited entry #" + x.tampered_seq + ". Now verify.");
    if (d) { setS(d.state); setVerdict(null); }
  }

  const m = S && S.metrics;
  const chain = S ? S.audit.slice(0, 7).reverse() : [];
  const broken = verdict && !verdict.ok ? verdict.broken_at : null;

  return (
    <main className="pg-evidence">
      <div className="wrap">
        <div className="page-head">
          <div className="eyebrow">Evidence · auditable proof</div>
          <h2 className="h2">Every decision, on the record.</h2>
          <p className="lead">Nothing on this page is typed in by hand. It is read from the gateway&apos;s decisions, the lineage log and an HMAC hash-chained audit log that shows exactly where someone edited it.</p>
        </div>

        <section className="block">
          <div className="stats" id="stats">
            {m ? (
              <>
                <Stat label="Gateway decisions" value={m.messages} note={m.accepted + " accepted · " + m.rejected + " rejected · " + m.blocked + " blocked"} />
                <Stat label="Tool calls" value={m.tool_requests} note={m.tool_allowed + " allowed · " + m.tool_blocked + " blocked · " + m.tool_pending + " paused"} />
                <Stat label="Attack messages" value={m.attack_attempts} note={m.attack_attempts ? m.attack_stopped + " stopped by the gateway" : "none sent yet"} />
                <Stat label="Unauthorized emails" value={m.unauthorized_emails} note={m.emails_delivered + " simulated deliveries in total"} cls={m.unauthorized_emails ? "red" : "green"} />
              </>
            ) : null}
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">1</span>Audit chain</h3>
            <div className="row">
              <button className="btn sm primary" id="verify" onClick={verify}>Verify chain</button>
              <button className="btn sm danger" id="tamper" onClick={tamper}>Simulate an intruder edit</button>
            </div>
          </div>
          <div className="card pad">
            <div className="chain" id="chain">
              {!S ? null : chain.length ? chain.map((e, i) => [
                i ? <div className="lnk" key={e.seq + "l"} /> : null,
                <div className={"blk" + (broken === e.seq ? " bad" : "")} key={e.seq}>
                  <div className="label">{"#" + e.seq + " · " + time(e.ts)}</div>
                  <div className="k">{e.kind}</div>
                  <div className="hsh">{"prev "}<b>{e.prev.slice(0, 10)}</b></div>
                  <div className="hsh">{"mac  "}<b>{e.mac.slice(0, 10)}</b></div>
                </div>,
              ]) : <div className="empty" style={{ width: "100%" }}>No entries yet.</div>}
            </div>
            <div className="verdict" id="verdict">
              {!shown ? <span className="muted">Press “Verify chain” to recompute every MAC from the first entry.</span>
                : shown.ok ? (
                  <><span className="statbig" style={{ color: "var(--mint)" }}>Intact</span><span className="muted">{shown.checked + " entries re-verified from the first one"}</span></>
                ) : (
                  <><span className="statbig red">{"Broken at #" + shown.broken_at}</span><span className="muted">{shown.why}</span></>
                )}
            </div>
            <div className="hash mono dim" id="head" style={{ fontSize: 12, marginTop: 14, overflowWrap: "anywhere" }}>
              {S ? "head " + S.audit_head + " · " + S.audit_count + " entries" : ""}
            </div>
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">2</span>Task reports</h3><span className="muted" style={{ fontSize: 13 }}>blast radius recomputed from lineage on every request</span></div>
          <div className="tasks" id="tasks">
            {!S ? null : tasks.length ? tasks.map((t) => (
              <button key={t.task_id} className={"btn sm" + (t.task_id === sel ? " primary" : "")} onClick={() => setPicked(t.task_id)}>{t.task_id + " · " + pretty(t.scenario)}</button>
            )) : <div className="empty" style={{ width: "100%" }}>No tasks yet. Run one on the Live demo page.</div>}
          </div>
          <div className="two" id="report">
            {!report || report.sel !== sel ? null : "error" in report ? <div className="empty">{report.error}</div> : <ReportCards sel={report.sel} r={report.r} />}
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="two">
            <div>
              <div className="sechead"><h3><span className="secnum">3</span>Outbox</h3><span className="tag">simulated</span></div>
              <div className="card pad">
                <div className="list" id="outbox">
                  {!S ? null : S.outbox.length ? S.outbox.slice(0, 12).map((r) => (
                    <div className="li" key={r.id}>
                      <span className={"tag " + (r.status === "SIMULATED_DELIVERY" ? "green" : r.status === "BLOCKED" ? "amber" : "red")}>
                        {r.kind === "soc_alert" ? "SOC alert" : r.status === "SIMULATED_DELIVERY" ? "simulated" : r.status}
                      </span>
                      <span>{(r.to || []).join(", ") || r.subject}</span>
                      <span className="sub">{(r.code ? r.code + " · " : "") + r.reason}</span>
                    </div>
                  )) : <div className="empty">Nothing sent or attempted yet.</div>}
                </div>
              </div>
            </div>
            <div>
              <div className="sechead"><h3><span className="secnum">4</span>Audit log</h3><span className="muted" id="count" style={{ fontSize: 13 }}>{S ? S.audit_count + " entries" : ""}</span></div>
              <div className="card pad">
                <div className="list" id="audit">
                  {S ? S.audit.slice(0, 14).map((e) => (
                    <div className="li" key={e.seq}>
                      <span className="mono dim">{"#" + e.seq}</span>
                      <span className="mono" style={{ fontSize: 12.5 }}>{e.kind}</span>
                      <span className="sub">{auditLine(e)}</span>
                    </div>
                  )) : null}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">5</span>What each refusal means</h3></div>
          <div className="card pad">
            <div className="codes" id="codes">
              {S ? Object.entries(S.codes).map(([k, v]) => <div className="code" key={k}><b>{k}</b><span className="soft">{v}</span></div>) : null}
            </div>
          </div>
        </section>

        <p className="muted" style={{ fontSize: 13, margin: "0 0 40px" }}>Prefer the dense operator view? <a href="/console" style={{ textDecoration: "underline" }}>Open the classic console</a>.</p>
      </div>
    </main>
  );
}
