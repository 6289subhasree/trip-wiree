"use client";
import React, { useEffect, useState } from "react";
import { Header } from "../../components/Header";

type AttackRun = {
  seq: number;
  kind: string;
  data: any;
};

export default function AttackerPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [runs, setRuns] = useState<AttackRun[]>([]);
  const [firewall, setFirewall] = useState(true);
  const [loading, setLoading] = useState(true);
  
  const refreshData = async () => {
    try {
      const [runsRes, summaryRes, fwRes] = await Promise.all([
        fetch("/api/attacks/runs"),
        fetch("/api/telemetry/summary"),
        fetch("/api/firewall/status")
      ]);
      const runsData = await runsRes.json();
      const summaryData = await summaryRes.json();
      const fwData = await fwRes.json();
      
      setRuns(runsData.runs || []);
      setMetrics(summaryData || {});
      setFirewall(fwData.enabled ?? true);
      setLoading(false);
    } catch (e) {
      console.error(e);
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 3000);
    return () => clearInterval(interval);
  }, []);

  const totalAttempts = metrics?.requests || 0;
  const successfulAttacks = metrics?.unsafe_executions || 0;
  const blockedAttacks = metrics?.blocked || 0;
  const successRate = totalAttempts > 0 ? ((successfulAttacks / totalAttempts) * 100).toFixed(1) : "0.0";

  return (
    <>
      <Header />
      <main className="screen" style={{ paddingTop: "120px", color: "var(--foreground)" }}>
        <div className="hero" style={{ padding: "0 2rem" }}>
          <span className="eyebrow">Red Team</span>
          <h1 style={{ fontSize: "2rem", marginBottom: "1rem" }}>Attacker Operations</h1>
          <p style={{ maxWidth: "800px", margin: "0 auto", color: "var(--gray-3)" }}>
            Monitor adversarial prompt injection attempts against the cognitive agent.
          </p>
        </div>

        <div style={{ maxWidth: "1200px", margin: "3rem auto", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem", padding: "0 1rem" }}>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Total Attempts</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem" }}>{totalAttempts}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Successful Bypasses</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem", color: "var(--color-danger)" }}>{successfulAttacks}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Blocked Attacks</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem", color: "var(--color-success)" }}>{blockedAttacks}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Success Rate</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem" }}>{successRate}%</p>
          </div>
        </div>

        <div style={{ maxWidth: "1200px", margin: "2rem auto", padding: "0 1rem" }}>
          <h2 style={{ fontSize: "1.5rem", marginBottom: "1rem" }}>Live Attack Feed</h2>
          {runs.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", background: "var(--surface)", borderRadius: "12px", border: "1px solid var(--border)", color: "var(--gray-3)" }}>
              No simulated attacks detected in this session.
            </div>
          ) : (
            <div style={{ background: "var(--surface)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", background: "rgba(0,0,0,0.2)" }}>
                    <th style={{ padding: "1rem" }}>Timestamp</th>
                    <th style={{ padding: "1rem" }}>Target</th>
                    <th style={{ padding: "1rem" }}>Action</th>
                    <th style={{ padding: "1rem" }}>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "1rem", color: "var(--gray-3)", fontFamily: "monospace" }}>
                        {new Date(run.data?.at * 1000 || Date.now()).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "1rem" }}>Agent 1 (Cognitive Writer)</td>
                      <td style={{ padding: "1rem", fontFamily: "monospace", fontSize: "0.9rem" }}>{run.data?.action || "Simulated Context Injection"}</td>
                      <td style={{ padding: "1rem" }}>
                        <span style={{ 
                          padding: "0.25rem 0.5rem", 
                          borderRadius: "4px", 
                          fontSize: "0.8rem", 
                          background: run.data?.decision === "BLOCKED" ? "rgba(40,167,69,0.1)" : "rgba(220,53,69,0.1)",
                          color: run.data?.decision === "BLOCKED" ? "var(--color-success)" : "var(--color-danger)",
                          fontWeight: "bold"
                        }}>
                          {run.data?.decision || "UNKNOWN"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </>
  );
}
