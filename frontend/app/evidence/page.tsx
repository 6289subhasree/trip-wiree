import type { Metadata } from "next";
import { EvidencePage } from "@/components/EvidencePage";
import "./evidence.css";

export const metadata: Metadata = { title: "TripWire · Evidence" };

export default function Page() {
  return <EvidencePage />;
}
