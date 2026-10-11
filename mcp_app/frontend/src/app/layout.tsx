import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { 
  Shield, 
  Activity, 
  Crosshair, 
  MessageSquare,
  LayoutDashboard
} from "lucide-react";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "TripWire — Runtime Containment",
  description: "Runtime containment and security gateway for autonomous AI agents",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-[#010102] text-[#f7f8f8] min-h-screen flex antialiased`}>
        {/* Minimal Linear-Style Sidebar */}
        <aside className="w-56 bg-[#08090a] border-r border-[#23252a] p-3 flex flex-col h-screen sticky top-0 shrink-0 z-20">
          {/* Brand */}
          <div className="flex items-center gap-2.5 px-2 py-2 mb-4">
            <div className="w-7 h-7 rounded-md bg-[#5e6ad2]/10 border border-[#5e6ad2]/25 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-[#828fff]" />
            </div>
            <span className="font-medium text-sm text-[#f7f8f8] tracking-tight">
              TripWire
            </span>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-0.5 flex-grow">
            <Link 
              href="/chat" 
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] transition-colors"
            >
              <MessageSquare className="w-4 h-4 text-[#8a8f98]" />
              <span>Chat</span>
            </Link>

            <Link 
              href="/defender" 
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] transition-colors"
            >
              <Activity className="w-4 h-4 text-[#8a8f98]" />
              <span>Defender SOC</span>
            </Link>

            <Link 
              href="/attacker" 
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-[#d0d6e0] hover:text-white hover:bg-[#141516] transition-colors"
            >
              <Crosshair className="w-4 h-4 text-[#8a8f98]" />
              <span>Attacker Lab</span>
            </Link>

            <Link 
              href="/" 
              className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs font-medium text-[#8a8f98] hover:text-white hover:bg-[#141516] transition-colors"
            >
              <LayoutDashboard className="w-4 h-4 text-[#8a8f98]" />
              <span>Overview</span>
            </Link>
          </nav>

          {/* Minimal Footer */}
          <div className="pt-3 border-t border-[#23252a] px-2 text-[11px] text-[#62666d] flex items-center justify-between">
            <span>Gateway</span>
            <span className="text-[#27a644] font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#27a644]"></span>
              Active
            </span>
          </div>
        </aside>

        {/* Main Content View */}
        <main className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
          <div className="flex-1 p-6 md:p-8 max-w-5xl w-full mx-auto">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
