import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "TripWire · Runtime containment for AI agents",
  description:
    "Untrusted content may supply evidence, but it can never grant authority. One gateway checks every AI agent tool call.",
};

export const viewport: Viewport = {
  themeColor: "#000000",
  colorScheme: "dark",
};

// Font slots. A rule is emitted only for a file that exists in public/assets/fonts when the page is built,
// so a missing font costs no request. Drop the .woff2 in and run `npm run build`.
const FONT_SLOTS = [
  { family: "Reference Sans", file: "ReferenceSans-Variable.woff2", weight: "100 900" },
  { family: "Reference Display", file: "ReferenceDisplay-Variable.woff2", weight: "400 900" },
];

const FONT_FACES = FONT_SLOTS.filter((slot) => existsSync(join(process.cwd(), "public", "assets", "fonts", slot.file)))
  .map(
    (slot) =>
      `@font-face{font-family:"${slot.family}";src:url("/assets/fonts/${slot.file}") format("woff2");` +
      `font-weight:${slot.weight};font-style:normal;font-display:swap}`,
  )
  .join("");

// Runs before first paint so the entrance timeline never flashes its end state.
const MOTION_BOOT = `(function(){try{if(window.matchMedia("(prefers-reduced-motion: reduce)").matches)return;var d=document.documentElement;d.classList.add("motion-pending");window.__motionFallback=setTimeout(function(){d.classList.remove("motion-pending")},3500)}catch(e){}})();`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {FONT_FACES && <style dangerouslySetInnerHTML={{ __html: FONT_FACES }} />}
        <script dangerouslySetInnerHTML={{ __html: MOTION_BOOT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
