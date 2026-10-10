/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useState } from "react";
import { Server, Zap } from "lucide-react";

export default function SystemStatus() {
  const [status, setStatus] = useState<any>(null);

  useEffect(() => {
    fetch("http://localhost:8000/api/system")
      .then(r => r.json())
      .then(setStatus)
      .catch(console.error);
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white mb-2">System Status</h1>
        <p className="text-zinc-400">Health, configuration, and connectivity metrics.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="glass-panel p-8">
          <div className="flex items-center space-x-4 mb-8 pb-4 border-b border-white/10">
            <div className="bg-zinc-800/50 p-3 rounded-lg border border-white/5">
              <Server className="w-6 h-6 text-blue-400" />
            </div>
            <h2 className="text-xl font-bold text-white">Backend Services</h2>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between items-center p-4 rounded-lg hover:bg-white/5 transition-colors">
              <span className="text-sm font-medium text-zinc-400">Control Plane API</span>
              <span className="text-sm font-bold text-green-400 flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span>Online</span>
              </span>
            </div>
            <div className="flex justify-between items-center p-4 rounded-lg hover:bg-white/5 transition-colors">
              <span className="text-sm font-medium text-zinc-400">MCP Gateway Server</span>
              <span className="text-sm font-bold text-green-400 flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span>Running (stdio)</span>
              </span>
            </div>
            <div className="flex justify-between items-center p-4 rounded-lg hover:bg-white/5 transition-colors">
              <span className="text-sm font-medium text-zinc-400">Data Store</span>
              <span className="text-sm font-bold text-zinc-300">Local JSONL</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-8">
          <div className="flex items-center space-x-4 mb-8 pb-4 border-b border-white/10">
            <div className="bg-zinc-800/50 p-3 rounded-lg border border-white/5">
              <Zap className="w-6 h-6 text-yellow-400" />
            </div>
            <h2 className="text-xl font-bold text-white">Ollama Configuration</h2>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between items-center p-4 rounded-lg hover:bg-white/5 transition-colors">
              <span className="text-sm font-medium text-zinc-400">Base URL</span>
              <span className="text-sm font-bold text-blue-400 font-mono bg-blue-900/20 px-3 py-1 rounded border border-blue-900/50">{status?.ollama_url || 'Loading...'}</span>
            </div>
            <div className="flex justify-between items-center p-4 rounded-lg hover:bg-white/5 transition-colors">
              <span className="text-sm font-medium text-zinc-400">Active Model</span>
              <span className="text-sm font-bold text-purple-400 font-mono bg-purple-900/20 px-3 py-1 rounded border border-purple-900/50">{status?.ollama_model || 'Loading...'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
