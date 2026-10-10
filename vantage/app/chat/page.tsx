"use client";

import { useState } from "react";
import { Header } from "@/components/Header";
import { Background } from "@/components/Background";

export default function ChatPage() {
  const [message, setMessage] = useState("");
  const [attackSimulation, setAttackSimulation] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim()) return;

    setLoading(true);
    setError("");
    setResponse(null);

    try {
      const res = await fetch("http://localhost:8000/api/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-TripWire-Client": "dashboard",
        },
        body: JSON.stringify({
          message,
          session_id: "demo-session",
          attack_simulation: attackSimulation,
        }),
      });

      if (!res.ok) {
        throw new Error(await res.text());
      }

      const data = await res.json();
      setResponse(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="viewport">
      <section className="screen">
        <Background />
        <Header />
        <section className="hero" style={{ alignItems: "flex-start", paddingTop: "var(--header-top)", overflowY: "auto", display: "block" }}>
          <div className="hero-content" style={{ margin: "40px auto", maxWidth: "800px", display: "block" }}>
            <p className="eyebrow" style={{ marginBottom: "1rem" }}>
              <i aria-hidden="true" />
              Agent 1 Chat Console
            </p>
            <h1 className="hero-title" style={{ fontSize: "var(--display-size)", lineHeight: "1.1", marginBottom: "1rem", textAlign: "left" }}>
              <span className="line line-one">
                <span className="line-reveal">Secure Agent Chat.</span>
              </span>
            </h1>
            <p className="hero-copy" style={{ textAlign: "left", maxWidth: "100%", marginBottom: "2rem" }}>
              Test the LLM agent email drafting capabilities. TripWire intercepts the tool call and ensures that
              untrusted content cannot grant authority.
            </p>

            <form onSubmit={handleSubmit} style={{ marginBottom: "40px", display: "flex", flexDirection: "column", gap: "16px" }}>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="E.g., Draft a sick-leave email for 12–13 October to manager@example.com."
                style={{ 
                  padding: "16px", 
                  width: "100%", 
                  height: "120px", 
                  borderRadius: "12px", 
                  background: "rgba(0, 0, 0, 0.5)", 
                  color: "white", 
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                  fontFamily: "inherit",
                  fontSize: "1rem",
                  resize: "vertical"
                }}
              />
              <div style={{ display: "flex", gap: "20px", alignItems: "center", flexWrap: "wrap" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                  <input 
                    type="checkbox" 
                    checked={attackSimulation}
                    onChange={(e) => setAttackSimulation(e.target.checked)} 
                    style={{ width: "16px", height: "16px" }}
                  />
                  Simulate Prompt Injection (Attack Mode)
                </label>
                <button 
                  type="submit" 
                  disabled={loading}
                  className="primary-cta"
                  style={{ marginLeft: "auto", cursor: loading ? "wait" : "pointer", opacity: loading ? 0.7 : 1, width: "auto" }}
                >
                  <span className="label">{loading ? "Processing..." : "Send Request"}</span>
                </button>
              </div>
            </form>

            {error && (
              <div style={{ color: "#ff8888", padding: "16px", border: "1px solid rgba(255,0,0,0.3)", background: "rgba(255,0,0,0.1)", borderRadius: "12px", marginBottom: "20px" }}>
                {error}
              </div>
            )}

            {response && (
              <div style={{ display: "flex", flexDirection: "column", gap: "24px", animation: "fade-in 0.5s ease-out" }}>
                
                <div style={{ background: "rgba(0, 0, 0, 0.5)", padding: "24px", borderRadius: "12px", border: "1px solid rgba(255, 255, 255, 0.1)" }}>
                  <h2 style={{ fontSize: "1.2rem", marginBottom: "16px", color: "var(--accent-blue)", display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "currentColor" }}></span>
                    Agent Intent Extraction
                  </h2>
                  <pre style={{ whiteSpace: "pre-wrap", fontSize: "0.9rem", color: "rgba(255,255,255,0.7)", margin: 0 }}>
                    {JSON.stringify(response.intent, null, 2)}
                  </pre>
                </div>

                <div style={{ background: "rgba(0, 0, 0, 0.5)", padding: "24px", borderRadius: "12px", border: "1px solid rgba(255, 255, 255, 0.1)" }}>
                  <h2 style={{ fontSize: "1.2rem", marginBottom: "16px", color: "var(--accent-blue)", display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "currentColor" }}></span>
                    Structured Proposal Generated
                  </h2>
                  <pre style={{ whiteSpace: "pre-wrap", fontSize: "0.9rem", color: "rgba(255,255,255,0.7)", margin: 0 }}>
                    {JSON.stringify(response.proposal, null, 2)}
                  </pre>
                </div>
                
                <div style={{ 
                  background: response.decision.outcome === "ACCEPTED" ? "rgba(0, 255, 0, 0.05)" : "rgba(255, 0, 0, 0.05)", 
                  padding: "24px", 
                  borderRadius: "12px", 
                  border: response.decision.outcome === "ACCEPTED" ? "1px solid rgba(0, 255, 0, 0.3)" : "1px solid rgba(255, 0, 0, 0.3)" 
                }}>
                  <h2 style={{ 
                    fontSize: "1.2rem", 
                    marginBottom: "16px", 
                    color: response.decision.outcome === "ACCEPTED" ? "#34d399" : "#ef4444",
                    display: "flex", alignItems: "center", gap: "8px"
                  }}>
                    <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "currentColor" }}></span>
                    TripWire Gateway Execution
                  </h2>
                  
                  <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: "8px 16px", color: "rgba(255,255,255,0.9)", fontSize: "0.95rem" }}>
                    <div style={{ color: "rgba(255,255,255,0.5)" }}>Outcome</div>
                    <div style={{ fontWeight: "bold" }}>{response.decision.outcome}</div>
                    
                    <div style={{ color: "rgba(255,255,255,0.5)" }}>Code</div>
                    <div>{response.decision.code}</div>
                    
                    <div style={{ color: "rgba(255,255,255,0.5)" }}>Reason</div>
                    <div>{response.decision.reason}</div>
                  </div>

                  {response.decision.tool && (
                    <div style={{ marginTop: "20px", paddingTop: "20px", borderTop: "1px solid rgba(255,255,255,0.1)" }}>
                      <div style={{ color: "rgba(255,255,255,0.5)", marginBottom: "8px", fontSize: "0.95rem" }}>Evaluation Flags</div>
                      <ul style={{ margin: 0, paddingLeft: "20px", color: "rgba(255,255,255,0.8)", fontSize: "0.9rem", display: "flex", flexDirection: "column", gap: "4px" }}>
                        {response.decision.tool.codes?.length > 0 ? response.decision.tool.codes.map((code: string, i: number) => (
                          <li key={i}>{code}</li>
                        )) : <li>No violations detected</li>}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </section>
      </section>
    </main>
  );
}
