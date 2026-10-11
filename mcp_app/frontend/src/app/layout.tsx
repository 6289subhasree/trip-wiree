import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { 
  Shield, 
  LayoutDashboard, 
  Terminal, 
  Crosshair, 
  Server, 
  Activity, 
  MessageSquare,
  Radio,
  Cpu,
  Lock
} from "lucide-react";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "TripWire V2 — Runtime Containment for AI Agents",
  description: "Enterprise-grade SOC telemetry and red team security gateway for autonomous AI agents",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-[#010102] text-[#f7f8f8] min-h-screen flex selection:bg-[#5e6ad2]/30 selection:text-white antialiased overflow-x-hidden`}>
        {/* Linear Sidebar Navigation */}
        <aside className="w-64 linear-sidebar p-3 flex flex-col h-screen sticky top-0 shrink-0 z-20">
          {/* Brand header */}
          <div className="flex items-center justify-between p-2 mb-4">
            <Link href="/" className="flex items-center space-x-2.5 group">
              <div className="w-8 h-8 rounded-md bg-[#5e6ad2]/15 border border-[#5e6ad2]/30 flex items-center justify-center group-hover:border-[#5e6ad2] transition-colors shadow-[0_0_12px_rgba(94,106,210,0.2)]">
                <Shield className="w-4 h-4 text-[#828fff]" />
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-sm text-[#f7f8f8] tracking-tight flex items-center gap-1.5">
                  TripWire
                  <span className="text-[10px] bg-[#141516] text-[#8a8f98] px-1.5 py-0.2 rounded border border-[#23252a] font-mono font-medium">v2.0</span>
                </span>
                <span className="text-[10.5px] text-[#8a8f98] font-mono leading-none">Security Console</span>
              </div>
            </Link>
          </div>

          {/* Quick status badge */}
          <div className="mx-2 mb-4 p-2 bg-[#0f1011] border border-[#23252a] rounded-md flex items-center justify-between text-xs font-mono">
            <span className="flex items-center gap-1.5 text-[#8a8f98]">
              <Radio className="w-3 h-3 text-[#00ff9d] animate-pulse" />
              SOC STATUS
            </span>
            <span className="text-[#00ff9d] font-semibold text-[11px] bg-[#00ff9d]/10 px-1.5 py-0.5 rounded border border-[#00ff9d]/20">
              ACTIVE
            </span>
          </div>

          {/* Navigation group */}
          <div className="space-y-1 flex-grow px-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[#62666d] px-2 py-1 mb-1 font-mono">
              // WORKSPACE
            </div>

            <Link 
              href="/defender" 
              className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] border border-transparent hover:border-[#23252a] transition-all group"
            >
              <Activity className="w-4 h-4 text-[#828fff] group-hover:text-[#00ff9d] transition-colors" />
              <span className="flex-1">Defender SOC</span>
              <span className="text-[10px] font-mono text-[#8a8f98] bg-[#010102] px-1 rounded border border-[#23252a]">LIVE</span>
            </Link>

            <Link 
              href="/attacker" 
              className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] border border-transparent hover:border-[#23252a] transition-all group"
            >
              <Crosshair className="w-4 h-4 text-[#f87171] group-hover:text-red-400 transition-colors" />
              <span className="flex-1">Attacker Lab</span>
              <span className="text-[10px] font-mono text-red-400/80 bg-red-950/20 px-1 rounded border border-red-900/30">RED</span>
            </Link>

            <Link 
              href="/chat" 
              className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] border border-transparent hover:border-[#23252a] transition-all group"
            >
              <MessageSquare className="w-4 h-4 text-[#00e5ff] group-hover:text-[#00e5ff] transition-colors" />
              <span className="flex-1">AI Agent Chat</span>
              <span className="text-[10px] font-mono text-[#00e5ff]/80 bg-cyan-950/20 px-1 rounded border border-cyan-900/30">MCP</span>
            </Link>

            <div className="pt-3 pb-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[#62666d] px-2 py-1 mb-1 font-mono">
                // SYSTEM
              </div>

              <Link 
                href="/agent" 
                className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#8a8f98] hover:text-white hover:bg-[#141516] transition-colors"
              >
                <Terminal className="w-4 h-4 text-[#8a8f98]" />
                <span>Agent Terminal CLI</span>
              </Link>

              <Link 
                href="/" 
                className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#8a8f98] hover:text-white hover:bg-[#141516] transition-colors"
              >
                <LayoutDashboard className="w-4 h-4 text-[#8a8f98]" />
                <span>Overview</span>
              </Link>

              <Link 
                href="/system" 
                className="flex items-center space-x-2.5 px-2.5 py-2 rounded-md text-xs font-medium text-[#8a8f98] hover:text-white hover:bg-[#141516] transition-colors"
              >
                <Server className="w-4 h-4 text-[#8a8f98]" />
                <span>Telemetry Node</span>
              </Link>
            </div>
          </div>

          {/* Bottom sidebar footer */}
          <div className="mt-auto pt-3 border-t border-[#23252a] px-2 space-y-2">
            <div className="flex items-center justify-between text-[11px] text-[#8a8f98] font-mono">
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3 text-[#5e6ad2]" />
                Ollama Engine
              </span>
              <span className="text-[#00ff9d]">llama3</span>
            </div>
            <div className="flex items-center justify-between text-[11px] text-[#8a8f98] font-mono">
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-[#5e6ad2]" />
                Recovery
              </span>
              <span className="text-[#828fff]">TW-JUDGE-42</span>
            </div>
          </div>
        </aside>

        {/* Main Content View */}
        <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
          {/* Cyber Telemetry Status Header */}
          <header className="cyber-topbar px-6 py-2.5 flex items-center justify-between shrink-0 sticky top-0 z-10 backdrop-blur-md bg-[#08090a]/90">
            <div className="flex items-center space-x-4">
              <span className="flex items-center gap-1.5 text-[#00ff9d]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00ff9d] animate-pulse"></span>
                SYS:OK
              </span>
              <span className="text-[#23252a]">|</span>
              <span className="text-[#00ff9d]">NET:ACTIVE</span>
              <span className="text-[#23252a]">|</span>
              <span className="text-[#00e5ff]">AI:ONLINE</span>
              <span className="text-[#23252a]">|</span>
              <span className="text-[#828fff]">GATEWAY:ENFORCED</span>
              <span className="text-[#23252a]">|</span>
              <span className="text-[#8a8f98]">MODE:RUNTIME_CONTAINMENT</span>
            </div>

            <div className="flex items-center space-x-3 text-[11px] text-[#8a8f98]">
              <span className="text-[#62666d]">CIVIC:LOCAL</span>
              <span className="text-[#23252a]">|</span>
              <span className="text-[#f7f8f8] font-semibold">TRIPWIRE KERNEL V2</span>
            </div>
          </header>

          {/* Page Body */}
          <main className="flex-1 p-6 md:p-8 max-w-[1440px] w-full mx-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
