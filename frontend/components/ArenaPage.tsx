"use client";
// Attack arena (event mode), ported from tripwire/web/arena.html: firewall states, the event
// stream, intrusion pressure and Agent 3's ten channel attacks. Rendered from /api/state only.
import { useCallback, useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { act, api, isBusy } from "@/lib/api";
import { time } from "@/lib/format";
import { setFirewall, toast } from "@/lib/ui";
import type { AttackResult, FirewallMode, GatewayDecision, Snapshot, StreamName } from "@/lib/types";

type Point = { v: number; e: string };

// Which nodes and links light up for the most recent gateway decision.
function pathway(S: Snapshot) {
  const c = { l1: "link", l2: "link", l3: "link", l4: "uplink", nMon: "node", nVal: "node", nMail: "node", nAdv: "node", last: "no traffic yet" };
  const d = S.feed[0];
  if (!d) return c;
  const attack = (d.origin || "").startsWith("attack:");
  const cls = d.outcome === "ACCEPTED" ? "ok" : "no";
  if (attack) { c.l4 = "uplink " + (cls === "ok" ? "" : "no"); c.nAdv = "node bad"; }
  else { c.l1 = "link " + cls; c.nMon = "node hot"; }
  if (d.outcome === "ACCEPTED" && d.message_type !== "action.email.send") { c.l2 = "link ok"; c.nVal = "node hot"; }
  const action = d.action || (d.message_type === "action.email.send" ? d : null);
  if (action) { c.l3 = "link " + (action.email ? "ok" : "no"); if (action.email) c.nMail = "node hot"; }
  c.last = "last: " + d.message_type + " from " + d.sender_id + " → " + d.outcome + " " + d.code;
  return c;
}

function Chips({ S, name, id }: { S: Snapshot; name: StreamName; id: string }) {
  const st = S.streams[name];
  return (
    <div className="evchips" id={id}>
      {st.events.map((e, i) => (
        <span key={i} className={"chip" + (i < st.pos ? " ok" : "") + (i === st.pos ? " now" : "")}><i />{e + " +" + S.events[e]}</span>
      ))}
    </div>
  );
}

function Bars({ history, threshold }: { history: Point[]; threshold: number }) {
  const W = 520, H = 220, top = 14, base = 196, n = Math.max(6, history.length);
  const y = (v: number) => base - ((base - top) * v) / 100;
  const bw = (W - 40) / n;
  return (
    <svg className="bars" id="bars" viewBox="0 0 520 220" preserveAspectRatio="none" aria-label="Risk score after each step">
      <line x1={30} x2={W} y1={y(threshold)} y2={y(threshold)} stroke="#ff2a3d" strokeDasharray="5 5" strokeWidth={1.2} />
      <text x={W - 4} y={y(threshold) - 6} textAnchor="end" fill="#ff6b78" fontSize={11} fontFamily="Consolas,monospace">{"alert threshold " + threshold}</text>
      <line x1={30} x2={W} y1={base} y2={base} stroke="rgba(255,255,255,.12)" />
      {history.map((pt, i) => {
        const x = 34 + i * bw, hgt = base - y(pt.v);
        return (
          <g key={i}>
            <rect x={x + 4} y={y(pt.v)} width={Math.max(6, bw - 12)} height={Math.max(1, hgt)} rx={8}
              fill={pt.v >= threshold ? "#ff2a3d" : "#a9e5cb"} opacity={pt.v >= threshold ? 1 : 0.85} />
            <text x={x + bw / 2} y={y(pt.v) - 7} textAnchor="middle" fill="#f3f0ea" fontSize={12} fontFamily="Segoe UI,system-ui">{String(pt.v)}</text>
            <text x={x + bw / 2} y={base + 16} textAnchor="middle" fill="#8a8693" fontSize={9.5} fontFamily="Consolas,monospace">{pt.e.slice(0, 12)}</text>
          </g>
        );
      })}
      {!history.length ? <text x={W / 2} y={H / 2} textAnchor="middle" fill="#5d5a66" fontSize={13}>Step a stream to plot Agent 1&apos;s risk score</text> : null}
    </svg>
  );
}

function Feed({ feed }: { feed: GatewayDecision[] }) {
  const groups: { d: GatewayDecision; n: number }[] = [];
  for (const d of feed) {
    const g = groups[groups.length - 1];
    if (g && g.d.message_type === d.message_type && g.d.code === d.code && g.d.origin === d.origin) g.n++;
    else groups.push({ d, n: 1 });
  }
  if (!groups.length) return <div className="feed" id="feed"><div className="empty">No traffic yet. Step a stream or launch an attack.</div></div>;
  return (
    <div className="feed" id="feed">
      {groups.slice(0, 12).map(({ d, n }) => (
        <div className="fr fade" key={d.seq}>
          <span className="mono dim">{time(d.at)}</span>
          <span>
            <div className="mono">{d.message_type}</div>
            <div className="dim" style={{ fontSize: 12 }}>{(d.origin || "").startsWith("attack:") ? "Agent 3 · " + (d.origin || "").slice(7) : d.sender_id}</div>
          </span>
          <span className="why">{d.code + " · " + d.reason + (d.would_fail ? " (also " + d.would_fail + ")" : "")}</span>
          <span className={"stamp " + d.outcome}>{d.outcome + (n > 1 ? " ×" + n : "")}</span>
        </div>
      ))}
    </div>
  );
}

export function ArenaPage() {
  const [S, setS] = useState<Snapshot | null>(null);
  const [history, setHistory] = useState<Point[]>([]);
  const [code, setCode] = useState("");
  const latest = useRef<Snapshot | null>(null);

  const apply = useCallback((d: Snapshot | { state: Snapshot } | null) => {
    const st = d && "state" in d ? d.state : d;
    if (!st || !st.firewall) return;
    latest.current = st;
    setFirewall(st.firewall.mode);
    setS(st);
  }, []);

  useEffect(() => {
    const load = () => api.state().then(apply);
    load().catch((e: Error) => toast("Cannot reach the TripWire server: " + e.message, true));
    let tick = 0;
    const timer = setInterval(() => {
      tick++;
      const fast = latest.current && latest.current.agents.adversary.run.running;
      if (!isBusy() && !document.hidden && (fast || tick % 4 === 0)) load().catch(() => setFirewall("OFFLINE"));
    }, 1000);
    return () => clearInterval(timer);
  }, [apply]);

  async function step(stream: StreamName) {
    const d = await act(() => api.streamStep(stream), (x) =>
      x.event + " → " + (x.decision ? x.decision.message_type + " " + x.decision.outcome : "no decision") +
      (x.decision && x.decision.action && x.decision.action.email ? " · SOC email sent" : ""));
    if (d) { setHistory((h) => [...h, { v: d.state.agents.monitor.score, e: d.event }]); apply(d); }
  }
  async function rewind() {
    const d = await act(() => api.streamReset(), "Streams rewound · score 0");
    if (d) { setHistory([]); apply(d); }
  }
  const mode = async (m: FirewallMode, msg: string) => apply(await act(() => api.firewall(m), msg));
  async function recover() {
    const d = await act(() => api.recover(code.trim()), "Recovered: NORMAL");
    if (d) { setCode(""); apply(d); }
  }

  if (!S) {
    return (
      <main className="pg-arena">
        <div className="wrap">
          <Head />
        </div>
      </main>
    );
  }

  const fw = S.firewall, m = S.agents.monitor, adv = S.agents.adversary, run = adv.run, mt = S.metrics;
  const over = m.score >= S.threshold;
  const p = S.pressure, pv = Math.min(100, (100 * p.value) / p.threshold);
  const riskRing = { "--v": m.score, "--c": over ? "var(--red)" : "var(--mint)" } as CSSProperties;
  const pRing = { "--v": pv, "--c": pv > 75 ? "var(--red)" : pv > 40 ? "var(--amber)" : "var(--mint)" } as CSSProperties;
  const path = pathway(S);
  const last: Record<string, AttackResult> = {};
  for (const r of S.attack_log) if (!last[r.scenario]) last[r.scenario] = r;

  return (
    <main className="pg-arena">
      <div className="wrap">
        <Head />

        <section className="block">
          <div className="top3">
            <div className="card pad fwcard">
              <div className="row" style={{ justifyContent: "space-between", margin: 0 }}><div className="label">Firewall</div><span className="tag" id="fwHow">{fw.automatic ? "automatic" : "manual"}</span></div>
              <div className={"mode " + fw.mode} id="fwMode">{fw.mode}</div>
              <div className="muted" id="fwReason" style={{ fontSize: 14, minHeight: 21 }}>{fw.reason + " · by " + fw.actor + " · " + time(fw.since)}</div>
              <div className="row">
                <button className="btn sm warn" id="bBlock" disabled={fw.mode !== "NORMAL"} onClick={() => mode("BLOCKING", "Kill switch engaged")}>Kill switch</button>
                <button className="btn sm" id="bRelease" disabled={fw.mode !== "BLOCKING"} onClick={() => mode("NORMAL", "Released")}>Release</button>
                <button className="btn sm danger" id="bLock" disabled={fw.mode === "LOCKDOWN"} onClick={() => mode("LOCKDOWN", "Emergency lockdown")}>Emergency lockdown</button>
              </div>
              <div className="row">
                <input className="in mono" id="code" placeholder="recovery code (server terminal)" autoComplete="off" value={code}
                  onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && fw.mode !== "NORMAL") recover(); }} />
                <button className="btn sm ok" id="bRecover" disabled={fw.mode === "NORMAL"} onClick={recover}>Recover</button>
              </div>
            </div>
            <div className="card pad ringcard">
              <div className="label">Agent 1 · risk score</div>
              <div className="ring" id="riskRing" style={riskRing}><div><b id="riskVal">{m.score}</b><small id="riskSub">{"threshold " + S.threshold}</small></div></div>
              <div className="muted" id="incident" style={{ fontSize: 13, minHeight: 20 }}>{m.incident ? "open incident " + m.incident : m.status}</div>
            </div>
            <div className="card pad ringcard">
              <div className="label">Intrusion pressure</div>
              <div className="ring" id="pRing" style={pRing}><div><b id="pVal">{Math.round(p.value)}</b><small id="pSub">{"lockdown at " + p.threshold}</small></div></div>
              <label className="row muted" style={{ fontSize: 13, justifyContent: "center" }}>
                <input type="checkbox" id="auto" checked={p.auto_lockdown}
                  onChange={async (e) => { const on = e.target.checked; apply(await act(() => api.autoLockdown(on), on ? "Auto-lockdown on" : "Auto-lockdown off")); }} /> automatic lockdown
              </label>
            </div>
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">1</span>The pathway</h3><span className="muted" id="lastLine" style={{ fontSize: 13 }}>{path.last}</span></div>
          <div className="card pad">
            <div className="path">
              <div className={path.nMon} id="nMon"><div className="n">AGENT 1</div><h4>Event monitor</h4><p id="tMon">{"score " + m.score + " · " + m.state}</p></div>
              <div className={path.l1} id="l1" />
              <div className={"node gw " + fw.mode} id="nGw"><div className="n">CHECKPOINT</div><h4>Gateway</h4><p id="tGw">{S.profile + " · " + fw.mode}</p></div>
              <div className={path.l2} id="l2" />
              <div className={path.nVal} id="nVal"><div className="n">AGENT 2</div><h4>Validator</h4><p id="tVal">{S.agents.validator.handled + " handled · " + S.agents.validator.state}</p></div>
              <div className={path.l3} id="l3" />
              <div className={path.nMail} id="nMail"><div className="n">ACTION</div><h4>SOC email</h4><p id="tMail">{mt.emails_delivered + " simulated · " + mt.email_denied + " denied"}</p></div>
            </div>
            <div className="advrow"><div className={path.l4} id="l4" /></div>
            <div className="advrow"><div className={path.nAdv} id="nAdv"><div className="n">AGENT 3</div><h4>Adversary</h4><p id="tAdv">{adv.state === "attacking" ? "running " + (run.current || "") : "idle · not a registered agent"}</p></div></div>
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">2</span>Event stream</h3>
            <div className="row">
              <button className="btn sm primary" id="sInc" onClick={() => step("incident")}>Step incident</button>
              <button className="btn sm" id="sBase" onClick={() => step("baseline")}>Step baseline</button>
              <button className="btn sm ghost" id="sRew" onClick={rewind}>Rewind</button>
              <button className="btn sm warn" id="sAlert" onClick={async () => apply(await act(() => api.alert(), (x) => "alert: " + (x.decision ? x.decision.outcome + " " + x.decision.code : "no decision")))}>Attempt alert now</button>
            </div>
          </div>
          <div className="card pad stream">
            <div>
              <div className="label">Incident stream</div>
              <Chips S={S} name="incident" id="incChips" />
              <div className="label" style={{ marginTop: 18 }}>Baseline stream</div>
              <Chips S={S} name="baseline" id="baseChips" />
              <p className="muted" style={{ fontSize: 13, marginTop: 18 }}>score = min(100, 0.8 × previous + event weight). A heuristic severity index, not a probability. Deterministic, so the demo repeats exactly.</p>
            </div>
            <Bars history={history} threshold={S.threshold} />
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">3</span>Channel attacks</h3>
            <div className="row">
              <span className="muted" id="seq" style={{ fontSize: 13 }}>
                {run.running ? "running " + run.done + "/" + run.total + " · " + (run.current || "")
                  : run.finished_at ? "last run " + run.done + "/" + run.total + (run.lockdown_after_s != null ? " · auto-LOCKDOWN after " + run.lockdown_after_s + "s" : "") : ""}
              </span>
              <button className="btn sm red" id="bSeq" disabled={run.running} onClick={async () => apply(await act(() => api.attackSuite(), "Agent 3 is running all 10 attacks"))}>Run all 10</button>
              <button className="btn sm" id="bStop" disabled={!run.running} onClick={async () => apply(await act(() => api.attackStop(), "Agent 3 stopped"))}>Stop</button>
            </div>
          </div>
          <div className="atk" id="atk">
            {S.scenarios.map((sc) => {
              const r = last[sc.id];
              return (
                <div className="card ac" key={sc.id}>
                  <span className={"tag " + (sc.threat_model === "external" ? "" : sc.threat_model === "mitm" ? "amber" : "red")}>{sc.threat_model}</span>
                  <span className="t">{sc.title}</span><span className="d">{sc.description}</span>
                  <span className={"res " + (!r ? "dim" : r.outcome === "ACCEPTED" ? "red" : "green")}>
                    {!r ? "expect " + sc.expected : (r.outcome === "ACCEPTED" ? "PASSED · " : "STOPPED · ") + r.code}
                  </span>
                  <button className="btn sm" onClick={async () => apply(await act(() => api.attack(sc.id),
                    (d) => sc.title + ": " + [...new Set(d.results.map((x) => x.code))].join(", ")))}>Launch</button>
                </div>
              );
            })}
          </div>
        </section>

        <section className="block" style={{ paddingTop: 0 }}>
          <div className="sechead"><h3><span className="secnum">4</span>Gateway decisions</h3>
            <span className="muted" id="metrics" style={{ fontSize: 13 }}>{mt.messages + " messages · " + mt.rejected + " rejected · " + mt.blocked + " blocked by firewall · " + mt.unauthorized_emails + " unauthorized emails"}</span>
          </div>
          <div className="card pad"><Feed feed={S.feed} /></div>
        </section>
      </div>
    </main>
  );
}

function Head() {
  return (
    <div className="page-head">
      <div className="eyebrow">Attack arena · three agents</div>
      <h2 className="h2">Three agents. One firewall. Ten ways in.</h2>
      <p className="lead">Agent 1 watches a security event stream and raises an alert at risk 70. Agent 2 validates it before any email goes out. Agent 3 attacks the channel between them.</p>
    </div>
  );
}
