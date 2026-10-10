"use client";
// Shared top navigation and footer, ported from TW.nav() in tripwire/web/app.js.
// Plain <a> links on purpose: every page is a full load from the Python server, exactly like
// the original site, and /console is not a Next.js page at all.
import { usePathname } from "next/navigation";
import { useState } from "react";
import { useStore } from "@/lib/store";
import { firewallPill } from "@/lib/ui";

const LINKS: [href: string, label: string][] = [
  ["/", "Home"],
  ["/demo", "Live demo"],
  ["/arena", "Attack arena"],
  ["/evidence", "Evidence"],
  ["/console", "Console"],
];

export function Nav() {
  const path = (usePathname() || "/").replace(/(.)\/$/, "$1");
  const [open, setOpen] = useState(false);
  const mode = useStore(firewallPill, null);
  return (
    <header className="nav">
      <div className="wrap">
        <a className="brand" href="/" aria-label="TripWire home">
          <span className="mark" />
          TRIPWIRE
        </a>
        <nav className={"navlinks" + (open ? " open" : "")} id="navlinks">
          {LINKS.map(([href, label]) => (
            <a key={href} href={href} className={href === path ? "on" : undefined}>
              {label}
            </a>
          ))}
        </nav>
        <div className="navright">
          <a className={"fw" + (mode ? " " + mode : "")} id="fwPill" href="/arena" title="Live firewall state">
            <i />
            <span>{mode === null ? "FIREWALL ..." : mode === "OFFLINE" ? "SERVER OFFLINE" : "FIREWALL " + mode}</span>
          </a>
          {path === "/demo" ? null : (
            <a className="btn primary navcta" href="/demo">
              Run demo ↗
            </a>
          )}
          <button className="menu" aria-label="Menu" onClick={() => setOpen((v) => !v)}>
            Menu
          </button>
        </div>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <div className="wrap">
        <div>
          <b>TRIPWIRE</b>
          {"  ·  Constrain → Enforce → Prove  ·  Team HELLCODE  ·  HackInverse 1.0"}
        </div>
        <div>Local · offline · synthetic data · no email or upload ever leaves this machine</div>
      </div>
    </footer>
  );
}
