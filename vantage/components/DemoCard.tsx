"use client";
import { useEffect, useState } from "react";
import type { AnimationEvent } from "react";
import { apiGet, apiPost } from "@/lib/api";

declare global {
  interface Window {
    __motionFallback?: ReturnType<typeof setTimeout>;
  }
}

type Report = {
  severity: string;
  sensitive_records_exposed: number;
  sensitive_records_protected: number;
  canaries_exposed: number;
  canaries_protected: number;
};

type Replay = { replay: { baseline: { report: Report }; protected: { report: Report } } };
type Health = { ok: boolean; firewall: string };

type Live =
  | { status: "loading" }
  | { status: "offline" }
  | { status: "ready"; score: number; baseline: Report; guarded: Report };

// Same formula as the classic landing page: share of the records and canaries at stake that stayed inside.
function containment(report: Report): number {
  const safe = report.sensitive_records_protected + report.canaries_protected;
  const atStake = safe + report.sensitive_records_exposed + report.canaries_exposed;
  return atStake ? Math.round((100 * safe) / atStake) : 100;
}

export function DemoCard() {
  const [live, setLive] = useState<Live>({ status: "loading" });
  const [firewall, setFirewall] = useState("");

  // Every number on this card comes from a real baseline-vs-protected run on the backend.
  useEffect(() => {
    let cancelled = false;
    apiPost<Replay>("/api/replay", { scenario: "footer_injection" })
      .then((data) => {
        if (cancelled) return;
        const baseline = data.replay.baseline.report;
        const guarded = data.replay.protected.report;
        setLive({ status: "ready", score: containment(guarded), baseline, guarded });
      })
      .catch(() => {
        if (!cancelled) setLive({ status: "offline" });
      });
    apiGet<Health>("/api/health")
      .then((data) => {
        if (!cancelled) setFirewall(data.firewall);
      })
      .catch(() => {
        if (!cancelled) setFirewall("OFFLINE");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // The card is the last step of the entrance timeline: once it lands, drop the pending state.
  const onAnimationEnd = (event: AnimationEvent<HTMLElement>) => {
    if (event.target !== event.currentTarget) return;
    document.documentElement.classList.remove("motion-pending");
    clearTimeout(window.__motionFallback);
  };

  const ready = live.status === "ready";
  const pending = live.status === "loading" ? "…" : "--";
  const note =
    live.status === "ready"
      ? "Invoice footer injection, run twice just now"
      : live.status === "loading"
        ? "Running the invoice attack through the gateway…"
        : "Start the server: python -m tripwire serve";

  return (
    <article className="demo-card" onAnimationEnd={onAnimationEnd} aria-live="polite">
      <div className="card-body">
        <div className="demo-visual">
          <img src="/assets/watch-demo-thumbnail.svg" alt="" draggable={false} />
          <div className="score">
            <span className="score-label">Live containment</span>
            <span className={"score-value" + (ready && live.score < 100 ? " bad" : "")} id="containment-score">
              {ready ? live.score : pending}
              {ready && <small>%</small>}
            </span>
            <span className="score-note">{note}</span>
          </div>
        </div>
        <dl className="versus">
          <div className="versus-row bad">
            <dt>Without TripWire</dt>
            <dd>
              <b id="baseline-severity">{ready ? live.baseline.severity : pending}</b>
              <span id="baseline-records">
                {ready ? `${live.baseline.sensitive_records_exposed} records exposed` : "counterfactual run"}
              </span>
            </dd>
          </div>
          <div className={"versus-row " + (ready && live.guarded.sensitive_records_exposed > 0 ? "bad" : "good")}>
            <dt>With TripWire</dt>
            <dd>
              <b id="protected-severity">{ready ? live.guarded.severity : pending}</b>
              <span id="protected-records">
                {ready
                  ? `${live.guarded.sensitive_records_exposed} exposed · ${live.guarded.sensitive_records_protected} protected`
                  : "through the gateway"}
              </span>
            </dd>
          </div>
        </dl>
        <a className={"watch-button fw-" + (firewall || "pending").toLowerCase()} href="/arena" title="Live firewall state">
          <i aria-hidden="true" />
          <span id="firewall-state">
            {firewall === "OFFLINE" ? "Server offline" : "Firewall " + (firewall || "…")}
          </span>
        </a>
      </div>
    </article>
  );
}
