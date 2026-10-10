"use client";

import { useEffect, useState } from "react";
import { Shield, Activity, XCircle, AlertTriangle, PlayCircle, Crosshair } from "lucide-react";
import Link from "next/link";

export default function Overview() {
  const [metrics, setMetrics] = useState({ attacks_blocked: 0, simulations: 0, events_total: 0 });
  const [gatewayStatus, setGatewayStatus] = useState({ firewall_mode: "UNKNOWN", gateway_online: false });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [metricsRes, statusRes] = await Promise.all([
          fetch("http://localhost:8000/api/metrics"),
          fetch("http://localhost:8000/api/gateway/status")
        ]);
        
        if (metricsRes.ok) setMetrics(await metricsRes.json());
        if (statusRes.ok) setGatewayStatus(await statusRes.json());
      } catch (e) {
        console.error(e);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">TripWire Overview</h1>
          <p className="text-zinc-400">Deterministic runtime containment for autonomous AI agents.</p>
        </div>
        <div className="flex items-center space-x-3 bg-zinc-900 px-4 py-2 rounded-full border border-zinc-800">
          <div className={`w-2.5 h-2.5 rounded-full ${gatewayStatus.gateway_online ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
          <span className="text-sm font-medium text-zinc-300">Gateway {gatewayStatus.gateway_online ? 'Online' : 'Offline'}</span>
        </div>
      </div>

      {/* Primary Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-6 relative overflow-hidden group">
          <div className="absolute -right-4 -top-4 p-6 opacity-5 group-hover:opacity-10 transition-opacity"><Shield className="w-24 h-24 text-green-400" /></div>
          <p className="text-sm font-medium text-zinc-400 mb-1">Firewall Mode</p>
          <p className="text-2xl font-bold flex items-center space-x-2">
            <span className={gatewayStatus.firewall_mode === 'NORMAL' ? 'text-green-400' : gatewayStatus.firewall_mode === 'BYPASSED' ? 'text-yellow-400' : 'text-red-400'}>
              {gatewayStatus.firewall_mode}
            </span>
          </p>
        </div>
        
        <div className="glass-panel p-6 relative overflow-hidden group">
          <div className="absolute -right-4 -top-4 p-6 opacity-5 group-hover:opacity-10 transition-opacity"><XCircle className="w-24 h-24 text-red-400" /></div>
          <p className="text-sm font-medium text-zinc-400 mb-1">Attacks Blocked</p>
          <p className="text-3xl font-bold text-white">{metrics.attacks_blocked}</p>
        </div>

        <div className="glass-panel p-6 relative overflow-hidden group">
          <div className="absolute -right-4 -top-4 p-6 opacity-5 group-hover:opacity-10 transition-opacity"><AlertTriangle className="w-24 h-24 text-yellow-400" /></div>
          <p className="text-sm font-medium text-zinc-400 mb-1">Unsafe Simulations</p>
          <p className="text-3xl font-bold text-white">{metrics.simulations}</p>
        </div>

        <div className="glass-panel p-6 relative overflow-hidden group">
          <div className="absolute -right-4 -top-4 p-6 opacity-5 group-hover:opacity-10 transition-opacity"><Activity className="w-24 h-24 text-blue-400" /></div>
          <p className="text-sm font-medium text-zinc-400 mb-1">Total Events</p>
          <p className="text-3xl font-bold text-white">{metrics.events_total}</p>
        </div>
      </div>

      {/* Quick Links */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
        <div className="glass-panel p-8">
          <h2 className="text-xl font-bold text-white mb-4">Launch Local Agent</h2>
          <p className="text-sm text-zinc-400 mb-6 leading-relaxed">Start the terminal-based local agent using Ollama and the official MCP client SDK. The agent runs locally on your machine and communicates with the TripWire gateway via MCP stdio.</p>
          <div className="bg-black/50 border border-white/10 rounded-lg p-4 mb-6 font-mono">
            <code className="text-sm text-green-400">source venv/bin/activate && python -m agent.cli</code>
          </div>
          <Link href="/agent" className="btn-primary inline-flex items-center justify-center space-x-2 px-6 py-2.5 rounded-lg text-sm font-semibold w-fit">
            <PlayCircle className="w-4 h-4" />
            <span>Open Agent Console</span>
          </Link>
        </div>

        <div className="glass-panel p-8">
          <h2 className="text-xl font-bold text-white mb-4">Run Attack Scenarios</h2>
          <p className="text-sm text-zinc-400 mb-6 leading-relaxed">Test the deterministic policy engine by sending predefined prompt injection scenarios. You can test both NORMAL (Gateway active) and BYPASSED (Simulated execution) firewall modes.</p>
          <div className="mb-6 opacity-0 select-none hidden md:block" aria-hidden="true">
             Spacer for alignment
             <br/><br/>
          </div>
          <Link href="/attacker" className="btn-danger inline-flex items-center justify-center space-x-2 px-6 py-2.5 rounded-lg text-sm font-semibold w-fit">
            <Crosshair className="w-4 h-4" />
            <span>Open Attacker Lab</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
