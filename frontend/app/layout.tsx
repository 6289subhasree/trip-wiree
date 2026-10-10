import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Footer, Nav } from "@/components/Nav";
import { Toaster } from "@/components/Toaster";
// Offline by design: system fonts only (see app.css), no next/font, no remote assets.
import "./app.css";

export const metadata: Metadata = {
  title: "TripWire · Runtime containment for AI agents",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        {children}
        <Footer />
        <Toaster />
      </body>
    </html>
  );
}
