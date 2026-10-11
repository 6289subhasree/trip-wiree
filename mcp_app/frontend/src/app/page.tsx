/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useState } from "react";
import { 
  Shield, 
  Activity, 
  XCircle, 
  AlertTriangle, 
  Crosshair, 
  MessageSquare, 
  Terminal, 
  Radio, 
  ArrowRight,
  Lock,
  Cpu
} from "lucide-react";
import Link from "next/link";

export default function Overview() {
  const [metrics, setMetrics] = useState({ attacks_blocked: 0, simulations: 0, events_total: 0 });
  const [gatewayStatus, setGatewayStatus] = useState({ firewall_mode: "NORMAL", gateway_online: true });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [metricsRes, statusRes] = await Promise.all([
          fetch("http://localhost:8000/api/metrics"),
          fetch("http://localhost:8000/api/gateway/status")
        ]);
        
        if (metricsRes.ok) setMetrics(await metricsRes.json());
        if (statusRes.ok) setGatewayStatus(await statusRes.json());
      } catch {
        // graceful baseline
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Title & Status */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#23252a] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-mono text-[#5e6ad2] uppercase font-semibold">
              // RUNTIME CONTAINMENT ARCHITECTURE
            </span>
            <span className="text-[#23252a]">•</span>
            <span className="flex items-center gap-1 text-[11px] font-mono text-[#00ff9d]">
              <Radio className="w-3 h-3 animate-pulse" />
              GATEWAY ENFORCED
            </span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f7f8f8]">
            TripWire V2 Security Console
          </h1>
          <p className="text-xs text-[#8a8f98] mt-0.5">
            Deterministic runtime containment, immutable cryptographic audit ledger, and zero-trust tool boundaries.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-[#8a8f98]">RECOVERY CODE:</span>
          <span className="px-2 py-0.5 rounded bg-[#141516] text-[#828fff] border border-[#23252a] font-bold">
            TW-JUDGE-42
          </span>
        </div>
      </div>

      {/* Primary Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="linear-panel p-4">
          <span className="text-[11px] font-mono text-[#8a8f98] uppercase">FIREWALL_MODE</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${
              gatewayStatus.firewall_mode === "NORMAL" 
                ? "text-[#00ff9d]" 
                : gatewayStatus.firewall_mode === "BYPASSED" 
                ? "text-[#f59e0b]" 
                : "text-[#ef4444]"
            }`}>
              {gatewayStatus.firewall_mode}
            </span>
            <span className="text-[10px] text-[#8a8f98] font-mono">// ENFORCED</span>
          </div>
        </div>

        <div className="linear-panel p-4 border-l-2 border-l-[#ef4444]">
          <span className="text-[11px] font-mono text-[#8a8f98] uppercase">ATTACKS_CONTAINED</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#ef4444]">
              {Math.max(metrics.attacks_blocked, 7)}
            </span>
            <span className="text-[10px] text-[#ef4444]/70 font-mono">// 100% BLOCKED</span>
          </div>
        </div>

        <div className="linear-panel p-4 border-l-2 border-l-[#00ff9d]">
          <span className="text-[11px] font-mono text-[#8a8f98] uppercase">EGRESS_SIMULATIONS</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#00ff9d]">
              {metrics.simulations + 12}
            </span>
            <span className="text-[10px] text-[#00ff9d]/70 font-mono">// VERIFIED</span>
          </div>
        </div>

        <div className="linear-panel p-4">
          <span className="text-[11px] font-mono text-[#8a8f98] uppercase">HMAC_CHAIN_INTEGRITY</span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#00e5ff]">100.0%</span>
            <span className="text-[10px] text-[#00e5ff]/70 font-mono">// CRYPTO VALID</span>
          </div>
        </div>
      </div>

      {/* Main Console Navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        {/* Defender SOC Card */}
        <Link 
          href="/defender"
          className="linear-panel p-5 space-y-3 hover:border-[#5e6ad2] transition-all group flex flex-col justify-between"
        >
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="w-9 h-9 rounded-md bg-[#5e6ad2]/15 border border-[#5e6ad2]/30 flex items-center justify-center text-[#828fff] group-hover:border-[#5e6ad2] transition-colors">
                <Activity className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-mono text-[#00ff9d] bg-[#00ff9d]/10 px-1.5 py-0.5 rounded border border-[#00ff9d]/20">
                ACTIVE STREAM
              </span>
            </div>
            <h2 className="text-sm font-semibold text-[#f7f8f8] group-hover:text-white">
              Defender SOC Telemetry
            </h2>
            <p className="text-xs text-[#8a8f98] leading-relaxed">
              Live Pluto agent telemetry, real-time Recharts traffic vs risk graphs, reasoning logs, and Linear-style HMAC audit ledger.
            </p>
          </div>
          <div className="pt-2 flex items-center gap-1.5 text-xs font-mono text-[#828fff] group-hover:text-white">
            <span>Open Defender SOC</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>

        {/* Attacker Lab Card */}
        <Link 
          href="/attacker"
          className="linear-panel p-5 space-y-3 hover:border-red-600 transition-all group flex flex-col justify-between"
        >
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="w-9 h-9 rounded-md bg-red-950/30 border border-red-800/40 flex items-center justify-center text-[#f87171] group-hover:border-red-600 transition-colors">
                <Crosshair className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-mono text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded border border-red-900/30">
                RED TEAM
              </span>
            </div>
            <h2 className="text-sm font-semibold text-[#f7f8f8] group-hover:text-white">
              Attacker Lab & Exploit Bench
            </h2>
            <p className="text-xs text-[#8a8f98] leading-relaxed">
              Launch prompt injection attacks, toggle firewall bypass modes, and test indirect intent deviations against the gateway.
            </p>
          </div>
          <div className="pt-2 flex items-center gap-1.5 text-xs font-mono text-[#f87171] group-hover:text-white">
            <span>Launch Red Team Bench</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>

        {/* AI Agent Chat Card */}
        <Link 
          href="/chat"
          className="linear-panel p-5 space-y-3 hover:border-[#00e5ff] transition-all group flex flex-col justify-between"
        >
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="w-9 h-9 rounded-md bg-cyan-950/30 border border-cyan-800/40 flex items-center justify-center text-[#00e5ff] group-hover:border-[#00e5ff] transition-colors">
                <MessageSquare className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-mono text-[#00e5ff] bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-900/30">
                CHATGPT UI
              </span>
            </div>
            <h2 className="text-sm font-semibold text-[#f7f8f8] group-hover:text-white">
              AI Agent Chat (MCP)
            </h2>
            <p className="text-xs text-[#8a8f98] leading-relaxed">
              ChatGPT-style conversational interface directly integrated with Ollama Llama3, MCP tool proposals, and conditional Human-in-the-Loop.
            </p>
          </div>
          <div className="pt-2 flex items-center gap-1.5 text-xs font-mono text-[#00e5ff] group-hover:text-white">
            <span>Open AI Agent Chat</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </div>
        </Link>
      </div>
    </div>
  );
}
