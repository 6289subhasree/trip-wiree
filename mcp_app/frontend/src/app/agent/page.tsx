"use client";

import { Terminal } from "lucide-react";

export default function AgentConsole() {
  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Agent Console</h1>
        <p className="text-zinc-400">Instructions and status for the V2 Terminal Agent.</p>
      </div>

      <div className="glass-panel p-8">
        <h2 className="text-xl font-bold text-blue-400 mb-4 flex items-center space-x-3">
          <div className="bg-blue-900/30 p-2 rounded-lg border border-blue-500/30">
            <Terminal className="w-6 h-6" />
          </div>
          <span>The main interaction happens in your terminal</span>
        </h2>
        <p className="text-base text-zinc-300 mb-8 leading-relaxed max-w-3xl">
          TripWire V2 utilizes a real terminal-based agent powered by a local Ollama model. 
          It communicates directly with the TripWire MCP server via the official MCP SDK using standard stdio.
        </p>

        <div className="bg-black/60 border border-white/10 rounded-xl p-6 mb-6">
          <p className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-4">Start the Terminal Agent:</p>
          <code className="text-sm font-mono text-green-400 block leading-loose">
            cd mcp_app<br/>
            source venv/bin/activate<br/>
            python -m agent.cli
          </code>
        </div>
        
        <p className="text-sm text-zinc-500 flex items-start space-x-2 bg-white/5 p-4 rounded-lg">
          <span className="font-bold text-yellow-500">Note:</span>
          <span>Ensure that the Ollama service is running locally (<code className="text-yellow-400/80 bg-black/40 px-1 rounded">http://localhost:11434</code>) and that you have pulled at least one model (e.g. <code className="text-yellow-400/80 bg-black/40 px-1 rounded">llama3</code>).</span>
        </p>
      </div>
    </div>
  );
}
