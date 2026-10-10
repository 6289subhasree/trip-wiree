import type { Metadata } from "next";
import { ArenaPage } from "@/components/ArenaPage";
import "./arena.css";

export const metadata: Metadata = { title: "TripWire · Attack arena" };

export default function Page() {
  return <ArenaPage />;
}
