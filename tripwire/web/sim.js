/* TripWire simulation page. The backend runs the whole pipeline and returns its recorded
   decisions; this file only replays them step by step. Server values are inserted as text. */
"use strict";
(() => {
  const {$, h, fill, toast, api, time} = TW;
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const STEP_MS = REDUCED ? 0 : 520;
  const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
  const count = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  const NODES = ["node-user", "node-agent1", "node-agent2", "node-egress", "node-agent3"];
  const LINKS = ["link-user", "link-agent1", "link-agent2", "link-agent3"];
  const WHO = {you: ["me", "You"], agent: ["a1", "Agent 1"], hijacked: ["a1 bad", "Agent 1 (hijacked)"],
               gateway: ["gw", "Agent 2"], error: ["err", "Error"]};

  class SimulationController {
    constructor() {
      this.firewall = true;   // TripWire enforcement on
      this.armed = false;     // Agent 3 attacking
      this.running = false;
      $("fw-toggle").addEventListener("click", () => this.setFirewall(!this.firewall));
      $("attack-btn").addEventListener("click", () => this.toggleAttack());
      $("chat").addEventListener("submit", (e) => { e.preventDefault(); this.run(); });
      this.setFirewall(true);
      this.reset();
    }

    // ------------------------------------------------------------ controls
    setFirewall(on) {
      this.firewall = on;
      document.body.dataset.fw = on ? "on" : "off";
      $("fw-toggle").setAttribute("aria-checked", String(on));
      fill("fw-state", on ? "TripWire ON" : "TripWire OFF");
      fill("fw-note", on ? "Strict gateway: every proposal is checked before a tool runs."
                         : "Counterfactual baseline in a throwaway session: nothing is checked.");
      fill("node-agent2-sub", on ? "reviews at the TripWire gateway" : "checks skipped (firewall off)");
    }

    setArmed(on) {
      this.armed = on;
      fill("attack-btn", on ? "Stop attack" : "Launch attack");
      const tag = $("attack-state");
      tag.className = "tag" + (on ? " red" : "");
      fill(tag, on ? "Agent 3 attacking" : "Agent 3 idle");
    }

    toggleAttack() {
      if (this.armed) { this.setArmed(false); return; }
      this.setArmed(true);
      this.run();
    }

    setLoading(on) {
      this.running = on;
      $("chat-send").classList.toggle("loading", on);
      for (const id of ["chat-send", "fw-toggle", "attack-btn"]) $(id).disabled = on;
      for (const b of document.querySelectorAll("#approvals button")) b.disabled = on;
      const tag = $("run-state");
      tag.className = "tag" + (on ? " amber" : "");
      fill(tag, on ? "Running" : "Waiting");
    }

    setState(id, state) { $(id).dataset.state = state || ""; }

    reset() {
      NODES.concat(LINKS).forEach((id) => this.setState(id, ""));
      if (!this.firewall) this.setState("node-agent2", "off");
      fill("attack-log", h("div", {class: "ln idle"}, "No attack traffic yet."));
      fill("threat-log", h("div", {class: "none"}, "No gateway decisions yet. Send an instruction below."));
      fill("egress", h("div", {class: "none"}, "Nothing has been sent."));
      fill("approvals");
      $("appr-label").classList.add("hidden");
      $("verdict").className = "verdict hidden";
    }

    // "You: ..." starts a new exchange; anything else replaces the reply line.
    say(who, text) {
      const [cls, label] = WHO[who];
      const line = h("span", {class: cls, title: text}, `${label}: ${text}`);
      if (who === "you") { fill("chat-log", line); return; }
      const log = $("chat-log");
      while (log.children.length > 1) log.removeChild(log.lastChild);
      log.appendChild(line);
    }

    // ------------------------------------------------------------ one run
    async run() {
      if (this.running) return;
      const prompt = $("chat-input").value.trim();
      if (!prompt) { toast("Type an instruction for Agent 1 first", true); $("chat-input").focus(); return; }
      this.setLoading(true);
      this.reset();
      this.say("you", prompt);
      this.setState("node-user", "active");
      this.setState("node-agent1", "thinking");
      try {
        const result = await api("/api/demo/execute",
          {firewall_active: this.firewall, human_prompt: prompt, attack_active: this.armed});
        await this.play(result);
      } catch (e) {
        this.reset();
        this.say("error", e.message);
        toast(e.message, true);
      } finally {
        this.setLoading(false);
      }
    }

    async decide(runId, approvalId, decision) {
      if (this.running) return;
      this.setLoading(true);
      try {
        const result = await api("/api/demo/approval", {run_id: runId, approval_id: approvalId, decision});
        fill("threat-log", result.steps.map((s) => this.ledgerRow(s)));
        this.finish(result);
      } catch (e) {
        this.say("error", e.message);
        toast(e.message, true);
      } finally {
        this.setLoading(false);
      }
    }

    async play(r) {
      const term = $("attack-log"), ledger = $("threat-log");
      fill(ledger);
      this.setState("link-user", "ok");
      if (r.attack_log.length) {
        fill(term);
        this.setState("node-agent3", "bad");
        this.setState("link-agent3", "no");
        for (const a of r.attack_log) {
          term.appendChild(h("div", {class: "ln"}, h("span", {class: "t"}, `[${time(a.at)}] `),
            `agent-3 > ${a.vector} → ${a.channel}`, h("span", {class: "pay"}, a.payload)));
          term.scrollTop = term.scrollHeight;
          await sleep(STEP_MS);
        }
      } else {
        fill(term, h("div", {class: "ln idle"}, "Agent 3 was idle in this run."));
      }

      for (const s of r.steps) {
        const hostile = s.origin !== "task";
        this.setState(s.actor === "Agent 3" ? "node-agent3" : "node-agent1", hostile ? "bad" : "thinking");
        this.setState("link-agent1", hostile ? "no" : "ok");
        if (s.enforced) this.setState("node-agent2", "thinking");
        await sleep(STEP_MS);
        ledger.appendChild(this.ledgerRow(s));
        ledger.scrollTop = ledger.scrollHeight;
        if (s.enforced) this.setState("node-agent2", "ok");
        if (s.executed) {
          this.setState("link-agent2", hostile ? "no" : "ok");
          this.setState("node-egress", hostile ? "bad" : "ok");
        } else if (s.enforced) {
          this.setState("link-agent2", "cut");
        }
        if (hostile) {
          const paused = s.decision === "REQUIRE_APPROVAL";
          term.appendChild(h("div", {class: "ln"}, h("span", {class: "t"}, `[${time(s.at)}] `),
            h("span", {class: s.executed ? "hit" : "miss"},
              s.executed ? "DELIVERED " : paused ? "HELD FOR HUMAN " : `DENIED ${s.code} `),
            `${s.tool}${s.to ? " → " + s.to : ""}`));
          term.scrollTop = term.scrollHeight;
        }
        await sleep(STEP_MS);
      }
      this.finish(r);
    }

    ledgerRow(s) {
      const a = s.approval;
      let stamp = "SKIPPED";
      if (s.decision === "BLOCK") stamp = "BLOCK";
      else if (s.decision === "REQUIRE_APPROVAL") {
        stamp = !a || a.status === "PENDING" ? "PAUSED" : a.status === "EXECUTED" ? "APPROVED"
          : a.status === "REJECTED" ? "REJECTED" : "BLOCK";
      } else if (s.executed) stamp = s.enforced ? "ALLOW" : "UNCHECKED";
      const chips = s.codes.length ? h("div", {class: "chips"},
        s.enforced ? null : "strict gateway would record:", s.codes.map((c) => h("code", null, c))) : null;
      return h("div", {class: "lr fade"},
        h("span", {class: "tm mono"}, time(s.at)),
        h("span", {class: "stamp " + stamp}, stamp),
        h("div", null,
          h("b", null, `${s.actor} · ${s.tool}${s.to ? " → " + s.to : ""}`),
          chips,
          h("p", null, s.reason),
          s.review ? h("p", {class: "rev"}, s.review) : null,
          a && a.status !== "PENDING" ? h("p", {class: "rev"}, `Human decision (${a.decided_by}): ${a.reason}`) : null));
    }

    approvalCard(r, a) {
      return h("div", {class: "mail appr fade" + (a.untrusted_only ? " hostile" : "")},
        h("div", {class: "top"}, h("span", {class: "to"}, `${a.tool} → ${a.to}`),
          h("span", {class: "tag " + (a.untrusted_only ? "red" : "green")},
            a.untrusted_only ? "Evidence: untrusted document" : "Evidence: your instruction")),
        h("pre", null, a.body),
        h("p", null, a.untrusted_only
          ? "Agent 1 cites only a line from the note it read. The quote is real, and a document cannot authorise an action."
          : "Agent 1 cites your instruction, and the gateway found that text in the task record."),
        h("div", {class: "row"},
          h("button", {type: "button", class: "btn sm ok", onclick: () => this.decide(r.run_id, a.id, "approve")}, "Approve and send"),
          h("button", {type: "button", class: "btn sm danger", onclick: () => this.decide(r.run_id, a.id, "reject")}, "Reject")));
    }

    finish(r) {
      const rep = r.report;
      const pending = r.approvals.length;
      const hostileOut = r.egress.filter((m) => m.malicious).length;
      const stopped = r.steps.filter((s) => s.origin !== "task" && s.enforced && !s.executed
        && !(s.approval && s.approval.status === "PENDING")).length;
      const userMail = r.egress.find((m) => !m.malicious);
      const leakedTo = [...new Set(r.egress.filter((m) => m.records).map((m) => m.to))];

      this.setState("node-user", "active");
      this.setState("link-user", "ok");
      this.setState("node-agent1", r.compromised ? "bad" : "ok");
      this.setState("link-agent1", r.compromised ? "no" : "ok");
      this.setState("node-agent2", !r.firewall_active ? "off" : pending ? "thinking" : "ok");
      this.setState("node-egress", r.compromised ? "bad" : r.delivered ? "ok" : "");
      this.setState("link-agent2", r.compromised ? "no" : r.delivered ? "ok" : "cut");
      this.setState("node-agent3", r.attack_active ? "bad" : "");
      this.setState("link-agent3", r.attack_active ? "no" : "");

      const protectedText = rep.sensitive_records_protected ? `${count(rep.sensitive_records_protected, "customer record")} and ` +
        `${count(rep.canaries_protected, "canary token")} protected. ` : "";
      let title, text, tone = "good";
      if (r.compromised && !r.firewall_active) {
        tone = "bad";
        title = "Breached (counterfactual baseline)";
        text = `${count(hostileOut, "hostile email")} left unchecked. ` +
          (rep.sensitive_records_exposed ? `${count(rep.sensitive_records_exposed, "customer record")} and ` +
            `${count(rep.canaries_exposed, "canary token")} reached ${leakedTo.join(", ")}. ` : "") +
          (userMail ? "" : "The message you asked for was never sent.");
      } else if (r.compromised) {
        tone = "bad";
        title = "Attacker content sent with your approval";
        text = "The gateway flagged that email as backed only by untrusted content and left the decision to you.";
      } else if (pending) {
        tone = "wait";
        title = "Paused for your approval";
        text = (stopped ? `${count(stopped, "hostile request")} stopped outright. ` : "") + protectedText +
          `${count(pending, "email")} to an external mailbox ${pending === 1 ? "is" : "are"} waiting below. Nothing leaves until you decide.`;
      } else if (stopped) {
        title = "Contained";
        text = `${count(stopped, "hostile request")} stopped before any tool ran. ` + protectedText +
          (userMail ? "Your message was delivered." : "No message was delivered.");
      } else {
        tone = r.delivered ? "good" : "wait";
        title = r.delivered ? "Clean run" : "Nothing delivered";
        text = r.delivered ? "Nothing to block. Your message was delivered." : "No email left the gateway in this run.";
      }
      const verdict = $("verdict");
      verdict.className = "verdict fade " + tone;
      fill(verdict, h("b", null, title), h("p", null, text),
        r.soc_alert ? h("small", null, "Agent 2 raised a SOC alert for this task (simulated email to the on-call address).") : null,
        r.note ? h("small", null, r.note) : null);

      $("appr-label").classList.toggle("hidden", !pending);
      fill("approvals", r.approvals.map((a) => this.approvalCard(r, a)));

      fill("egress", r.egress.length ? r.egress.map((m) => h("div", {class: "mail fade " + (m.malicious ? "hostile" : "safe")},
        h("div", {class: "top"}, h("span", {class: "to"}, "To: " + m.to),
          h("span", {class: "tag " + (m.malicious ? "red" : "green")}, m.malicious ? "Attacker content" : "Your message")),
        h("pre", null, m.body),
        m.records ? h("div", {class: "leak"}, `Attached: ${count(m.records, "customer record")}, ${count(m.canaries, "canary token")}`) : null,
        h("small", null, `${m.id} · simulated delivery, nothing left this machine`)))
        : h("div", {class: "none"}, pending ? "Nothing has been sent yet." : "Nothing was sent."));

      const sent = r.final_egress;
      if (pending) this.say("gateway", `paused ${count(pending, "email")} for your approval`);
      else if (!sent) this.say("gateway", "no email was sent");
      else if (sent.malicious) this.say("hijacked", `sent "${sent.body}" to ${sent.to}`);
      else this.say("agent", `sent your message to ${sent.to} (simulated delivery)`);
    }
  }

  TW.nav("simulation");
  TW.health();
  new SimulationController();
})();
