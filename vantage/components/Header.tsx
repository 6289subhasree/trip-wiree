"use client";
import { useEffect, useRef, useState } from "react";

const LINKS = [
  { label: "Home", href: "/" },
  { label: "Demo", href: "/demo" },
  { label: "Arena", href: "/arena" },
  { label: "Evidence", href: "/evidence" },
];

// Must match the tablet and mobile breakpoints in globals.css where the menu toggle is shown.
const COLLAPSED =
  "(max-width: 619px), (min-width: 620px) and (max-width: 790px), (min-width: 620px) and (max-width: 1100px) and (orientation: portrait)";

export function Header() {
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const headerRef = useRef<HTMLElement>(null);
  const navRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const query = window.matchMedia(COLLAPSED);
    const sync = () => {
      setCollapsed(query.matches);
      if (!query.matches) setOpen(false);
    };
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (!open) return;
    navRef.current?.querySelector("a")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const onPointer = (event: PointerEvent) => {
      if (!headerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [open]);

  return (
    <header ref={headerRef} className={"header" + (open ? " menu-open" : "")}>
      <a className="brand" href="/" aria-label="TripWire home">
        <svg width="25" height="25" viewBox="0 0 25 25" aria-hidden="true">
          <defs>
            <clipPath id="brand-disc">
              <circle cx="12.5" cy="12.5" r="12.5" />
            </clipPath>
          </defs>
          <g clipPath="url(#brand-disc)">
            <rect width="25" height="25" fill="#ededed" />
            <path d="M12.5 1.5 18.6 12.5 12.5 23.5 6.4 12.5Z" fill="#050606" />
            <path d="M12.5 1.5 18.6 12.5 12.5 12.5Z" fill="#737778" />
            <path d="M6.4 12.5 12.5 12.5 12.5 23.5Z" fill="#0a0b0b" />
            <path d="M18.6 12.5 25 7.2V17.8Z" fill="#050606" />
            <path d="M6.4 12.5 0 7.2V17.8Z" fill="#737778" />
            <path d="M12.5 8.2 14.9 12.5 12.5 16.8 10.1 12.5Z" fill="#fafafa" />
          </g>
        </svg>
        <span className="brand-name">TRIPWIRE</span>
      </a>
      <div className="header-actions" id="tablet-navigation">
        <nav ref={navRef} className="nav" aria-label="Primary" inert={collapsed && !open}>
          {LINKS.map(({ label, href }, index) => (
            <a
              key={href}
              href={href}
              className={index === 0 ? "active" : undefined}
              aria-current={index === 0 ? "page" : undefined}
              onClick={() => setOpen(false)}
            >
              {label}
            </a>
          ))}
        </nav>
        <div className="time-panel">
          <span className="time-label">Team HELLCODE</span>
          <span className="time-value">HackInverse 1.0&nbsp; • &nbsp;11 Oct 2026</span>
        </div>
        <a className="sign-up" href="/demo" onClick={() => setOpen(false)}>
          <span>Run demo</span>
        </a>
      </div>
      <button
        className="menu-toggle"
        type="button"
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
        aria-controls="tablet-navigation"
        onClick={() => setOpen((value) => !value)}
      >
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden="true">
          <path className="bar bar-top" d="M4 8h14" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
          <path className="bar bar-bottom" d="M4 14h14" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      </button>
    </header>
  );
}
