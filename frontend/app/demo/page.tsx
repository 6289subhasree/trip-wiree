import type { Metadata } from "next";
import { DemoPage } from "@/components/DemoPage";
import "./demo.css";

export const metadata: Metadata = { title: "TripWire · Live demo" };

export default function Page() {
  return <DemoPage />;
}
