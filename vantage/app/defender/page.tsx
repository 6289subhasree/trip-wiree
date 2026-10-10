"use client";
import React, { useEffect, useState } from "react";
import { Header } from "../../components/Header";

type EventLedger = {
  seq: number;
  kind: string;
  data: any;
};

export default function DefenderPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [events, setEvents] = useState<EventLedger[]>([]);
  const [firewall, setFirewall] = useState({ enabled: true, mode: "NORMAL" });
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<EventLedger | null>(null);
  
  const refreshData = async () => {
    try {
      const [eventsRes, summaryRes, fwRes] = await Promise.all([
        fetch("/api/telemetry/events"),
        fetch("/api/telemetry/summary"),
        fetch("/api/firewall/status")
      ]);
      const eventsData = await eventsRes.json();
      const summaryData = await summaryRes.json();
      const fwData = await fwRes.json();
      
      setEvents(eventsData.events || []);
      setMetrics(summaryData || {});
      setFirewall(fwData || { enabled: true, mode: "NORMAL" });
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

  const toggleFirewall = async () => {
    const newEnabled = !firewall.enabled;
    // optimistic update
    setFirewall(prev => ({ ...prev, enabled: newEnabled }));
    await fetch("/api/firewall/config", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-TripWire-Client": "dashboard" },
      body: JSON.stringify({ enabled: newEnabled })
    });
    refreshData();
  };

  const totalRequests = metrics?.requests || 0;
  const approvedActions = metrics?.approved || 0;
  const blockedActions = metrics?.blocked || 0;
  const unsafeExecutions = metrics?.unsafe_executions || 0;
  const intentMismatches = metrics?.intent_mismatches || 0;

  return (
    <>
      <Header />
      <main className="screen" style={{ paddingTop: "120px", color: "var(--foreground)" }}>
        <div className="hero" style={{ padding: "0 2rem", position: "relative" }}>
          <span className="eyebrow">Blue Team</span>
          <h1 style={{ fontSize: "2rem", marginBottom: "1rem" }}>Defender Operations</h1>
          <p style={{ maxWidth: "800px", margin: "0 auto", color: "var(--gray-3)" }}>
            Security telemetry, policy enforcement, and gateway event ledger.
          </p>

          <div style={{ position: "absolute", right: "2rem", top: "0" }}>
            <button 
              onClick={toggleFirewall} 
              style={{
                padding: "0.5rem 1rem",
                borderRadius: "8px",
                border: "1px solid var(--border)",
                background: firewall.enabled ? "rgba(40,167,69,0.1)" : "rgba(220,53,69,0.1)",
                color: firewall.enabled ? "var(--color-success)" : "var(--color-danger)",
                cursor: "pointer",
                fontWeight: "bold",
                display: "flex",
                alignItems: "center",
                gap: "0.5rem"
              }}>
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "currentColor" }} />
              {firewall.enabled ? "GATEWAY ENFORCING" : "ENFORCEMENT BYPASSED"}
            </button>
          </div>
        </div>

        <div style={{ maxWidth: "1200px", margin: "3rem auto", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem", padding: "0 1rem" }}>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Total Requests</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem" }}>{totalRequests}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Approved Actions</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem", color: "var(--color-success)" }}>{approvedActions}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Blocked Actions</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem" }}>{blockedActions}</p>
          </div>
          <div style={{ background: "var(--surface)", padding: "1.5rem", borderRadius: "12px", border: "1px solid var(--border)" }}>
            <h3 style={{ color: "var(--gray-3)", fontSize: "0.9rem", textTransform: "uppercase" }}>Unsafe Executions</h3>
            <p style={{ fontSize: "2.5rem", fontWeight: "600", marginTop: "0.5rem", color: "var(--color-danger)" }}>{unsafeExecutions}</p>
          </div>
        </div>

        <div style={{ maxWidth: "1200px", margin: "2rem auto", padding: "0 1rem" }}>
          <h2 style={{ fontSize: "1.5rem", marginBottom: "1rem" }}>Security Event Ledger</h2>
          {events.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", background: "var(--surface)", borderRadius: "12px", border: "1px solid var(--border)", color: "var(--gray-3)" }}>
              No gateway events in this session.
            </div>
          ) : (
            <div style={{ background: "var(--surface)", borderRadius: "12px", border: "1px solid var(--border)", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", background: "rgba(0,0,0,0.2)" }}>
                    <th style={{ padding: "1rem" }}>Time</th>
                    <th style={{ padding: "1rem" }}>Type</th>
                    <th style={{ padding: "1rem" }}>Target</th>
                    <th style={{ padding: "1rem" }}>Decision</th>
                    <th style={{ padding: "1rem" }}>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, i) => (
                    <tr 
                      key={i} 
                      onClick={() => setSelectedEvent(ev)}
                      style={{ 
                        borderBottom: "1px solid var(--border)", 
                        cursor: "pointer", 
                        background: selectedEvent === ev ? "rgba(255,255,255,0.05)" : "transparent"
                      }}
                    >
                      <td style={{ padding: "1rem", color: "var(--gray-3)", fontFamily: "monospace" }}>
                        {new Date(ev.data?.at * 1000 || Date.now()).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "1rem", fontFamily: "monospace", fontSize: "0.9rem" }}>{ev.kind}</td>
                      <td style={{ padding: "1rem" }}>{ev.data?.action || "N/A"}</td>
                      <td style={{ padding: "1rem" }}>
                        <span style={{ 
                          padding: "0.25rem 0.5rem", 
                          borderRadius: "4px", 
                          fontSize: "0.8rem", 
                          background: ev.data?.outcome === "ACCEPTED" ? "rgba(40,167,69,0.1)" : "rgba(220,53,69,0.1)",
                          color: ev.data?.outcome === "ACCEPTED" ? "var(--color-success)" : "var(--color-danger)",
                          fontWeight: "bold"
                        }}>
                          {ev.data?.outcome || "INFO"}
                        </span>
                      </td>
                      <td style={{ padding: "1rem", color: "var(--gray-3)", fontSize: "0.9rem" }}>{ev.data?.reason || "-"}</td>
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
