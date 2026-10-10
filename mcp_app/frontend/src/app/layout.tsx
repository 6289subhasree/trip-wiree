import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { Shield, LayoutDashboard, Terminal, Crosshair, Server, Activity } from "lucide-react";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "TripWire V2 Console",
  description: "Runtime Containment for AI Agents",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-transparent text-zinc-300 min-h-screen flex selection:bg-green-500/30 selection:text-white`}>
        {/* Sidebar Navigation */}
        <nav className="w-64 glass-nav p-4 flex flex-col h-screen sticky top-0 shrink-0 z-10">
          <div className="flex items-center space-x-3 mb-10 p-2">
            <div className="bg-green-500/10 p-2 rounded-lg border border-green-500/20">
              <Shield className="w-6 h-6 text-green-400" />
            </div>
            <span className="font-bold text-white text-xl tracking-tight">TripWire</span>
            <span className="bg-zinc-800 text-xs px-2 py-0.5 rounded-full text-zinc-400 border border-zinc-700">V2</span>
          </div>

          <div className="space-y-2 flex-grow">
            <Link href="/" className="flex items-center space-x-3 px-3 py-3 rounded-lg text-sm text-zinc-400 hover:text-white hover:bg-white/5 transition-all group">
              <LayoutDashboard className="w-5 h-5 group-hover:text-green-400 transition-colors" />
              <span className="font-medium">Overview</span>
            </Link>
            <Link href="/agent" className="flex items-center space-x-3 px-3 py-3 rounded-lg text-sm text-zinc-400 hover:text-white hover:bg-white/5 transition-all group">
              <Terminal className="w-5 h-5 group-hover:text-blue-400 transition-colors" />
              <span className="font-medium">Agent Console</span>
            </Link>
            <Link href="/attacker" className="flex items-center space-x-3 px-3 py-3 rounded-lg text-sm text-zinc-400 hover:text-white hover:bg-white/5 transition-all group">
              <Crosshair className="w-5 h-5 group-hover:text-red-400 transition-colors" />
              <span className="font-medium">Attacker Lab</span>
            </Link>
            <Link href="/defender" className="flex items-center space-x-3 px-3 py-3 rounded-lg text-sm text-zinc-400 hover:text-white hover:bg-white/5 transition-all group">
              <Activity className="w-5 h-5 group-hover:text-purple-400 transition-colors" />
              <span className="font-medium">Defender / SOC</span>
            </Link>
          </div>

          <div className="pt-4 mt-auto border-t border-white/10">
            <Link href="/system" className="flex items-center space-x-3 px-3 py-3 rounded-lg text-sm text-zinc-400 hover:text-white hover:bg-white/5 transition-all group">
              <Server className="w-5 h-5 group-hover:text-zinc-200 transition-colors" />
              <span className="font-medium">System</span>
            </Link>
          </div>
        </nav>

        {/* Main Content Area */}
        <main className="flex-1 overflow-auto p-10 relative z-0">
          <div className="max-w-6xl mx-auto">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
