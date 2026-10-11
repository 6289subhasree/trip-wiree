"use client";

import { Terminal, Sparkles, Cpu, Radio, Shield, ExternalLink } from "lucide-react";
import Link from "next/link";

export default function AgentConsole() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div className="border-b border-[#23252a] pb-4">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[11px] font-mono text-[#5e6ad2] uppercase font-semibold">
            // RUNTIME AGENT NODE
          </span>
          <span className="text-[#23252a]">•</span>
          <span className="text-[11px] font-mono text-[#00ff9d] flex items-center gap-1">
            <Radio className="w-3 h-3 animate-pulse" />
            TELEMETRY HOOK ACTIVE
          </span>
        </div>
        <h1 className="text-2xl font-bold tracking-tight text-[#f7f8f8]">
          Agent Runtime & Terminal CLI Console
        </h1>
        <p className="text-xs text-[#8a8f98] mt-0.5">
          Real-time interface configuration for TripWire V2 Model Context Protocol (MCP) agents.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Terminal Agent Option */}
        <div className="linear-panel p-6 space-y-4 border-l-2 border-l-[#5e6ad2]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#5e6ad2]/15 border border-[#5e6ad2]/30 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-[#828fff]" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-[#f7f8f8]">Terminal CLI Agent</h2>
              <span className="text-[10px] font-mono text-[#8a8f98]">Local Python + MCP stdio</span>
            </div>
          </div>

          <p className="text-xs text-[#8a8f98] leading-relaxed">
            Interacts directly through stdio with the TripWire MCP server. Every prompt entered in the terminal emits live telemetry webhooks to the Defender SOC.
          </p>

          <div className="bg-[#010102] border border-[#23252a] rounded-md p-3.5 font-mono text-xs">
            <span className="text-[10px] text-[#62666d] uppercase block mb-1.5">// RUN IN TERMINAL:</span>
            <code className="text-[#00ff9d] leading-loose block">
              cd mcp_app<br/>
              source venv/bin/activate<br/>
              python -m agent.cli
            </code>
          </div>
        </div>

        {/* Web Chat Agent Option */}
        <div className="linear-panel p-6 space-y-4 border-l-2 border-l-[#00e5ff] flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-cyan-950/30 border border-cyan-800/40 flex items-center justify-center">
                <Sparkles className="w-4 h-4 text-[#00e5ff]" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-[#f7f8f8]">Browser AI Chat Agent</h2>
                <span className="text-[10px] font-mono text-[#8a8f98]">ChatGPT-Style Interface</span>
              </div>
            </div>

            <p className="text-xs text-[#8a8f98] leading-relaxed">
              Full conversational web interface with Ollama LLM reasoning, interactive tool proposals, and instant Human-in-the-Loop review.
            </p>

            <div className="bg-[#010102] border border-[#23252a] rounded-md p-3.5 text-xs font-mono text-[#8a8f98] space-y-1">
              <div className="flex justify-between">
                <span>MODEL:</span>
                <span className="text-[#00ff9d]">llama3 (local)</span>
              </div>
              <div className="flex justify-between">
                <span>GATEWAY:</span>
                <span className="text-[#828fff]">TripWire Kernel V2</span>
              </div>
            </div>
          </div>

          <Link
            href="/chat"
            className="w-full py-2.5 linear-btn-primary text-xs font-mono font-medium flex items-center justify-center gap-2"
          >
            Launch Browser AI Chat
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </div>
  );
}
