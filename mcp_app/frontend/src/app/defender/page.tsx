/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useState } from "react";
import { Activity, Clock } from "lucide-react";

export default function DefenderSOC() {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchEvents = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/events");
      if (res.ok) {
        const data = await res.json();
        // Sort newest first
        setEvents(data.events.reverse());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const ignore_fetchEvents_warning = () => fetchEvents();
    ignore_fetchEvents_warning();
    const int = setInterval(fetchEvents, 3000);
    return () => clearInterval(int);
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Defender / SOC</h1>
          <p className="text-zinc-400">Live telemetry and audit events from the TripWire Gateway.</p>
        </div>
        <button onClick={fetchEvents} className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-4 py-2 rounded text-sm transition-colors">
          Refresh
        </button>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="p-5 border-b border-white/10 bg-black/40 flex justify-between items-center">
          <h2 className="text-sm font-bold text-white flex items-center space-x-2 tracking-wide">
            <Activity className="w-5 h-5 text-purple-400" />
            <span>Audit Log</span>
          </h2>
          <span className="text-xs font-medium text-zinc-400 bg-white/5 px-3 py-1 rounded-full border border-white/10">{events.length} events recorded</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-zinc-300">
            <thead className="bg-black/60 text-xs uppercase text-zinc-500 font-bold tracking-wider">
              <tr>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Event Type</th>
                <th className="px-6 py-4">Actor</th>
                <th className="px-6 py-4">Outcome</th>
                <th className="px-6 py-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-zinc-500 italic">
                    No events recorded yet.
                  </td>
                </tr>
              )}
              {events.map((e, idx) => {
                const details = e.details;
                const outcome = details?.outcome || 'INFO';
                const isBlocked = outcome === 'BLOCKED' || outcome === 'REJECTED';
                const isAccepted = outcome === 'ACCEPTED' || outcome === 'ALLOW';
                const isBypassed = outcome === 'BYPASSED' || e.event === 'mcp.bypassed';
                const proposal = details?.proposal;
                
                return (
                  <tr key={idx} className="hover:bg-white/5 transition-colors group">
                    <td className="px-6 py-4 whitespace-nowrap flex items-center space-x-3">
                      <Clock className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400 transition-colors" />
                      <span className="font-medium text-zinc-400">{new Date(e.at * 1000).toLocaleTimeString()}</span>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-blue-400">{e.event}</td>
                    <td className="px-6 py-4 font-medium">{e.actor}</td>
                    <td className="px-6 py-4">
                      <span className={`px-3 py-1.5 rounded-md text-xs font-bold tracking-wide
                        ${isBlocked ? 'bg-red-500/20 text-red-400 border border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]' : 
                          isAccepted ? 'bg-green-500/20 text-green-400 border border-green-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]' : 
                          isBypassed ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 shadow-[0_0_10px_rgba(234,179,8,0.2)]' : 
                          'bg-white/5 text-zinc-300 border border-white/10'}`}
                      >
                        {isBypassed ? 'BYPASSED' : outcome}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs max-w-sm truncate text-zinc-400" title={JSON.stringify(details)}>
                      {details?.reason || e.reason || (proposal ? `Tool: ${proposal.action_type}` : JSON.stringify(details))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
