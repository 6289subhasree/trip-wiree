// Display helpers ported from tripwire/web/app.js.
export const fmtINR = (n: number | null | undefined): string => "₹" + Number(n || 0).toLocaleString("en-IN");

export const time = (t: number | null | undefined): string =>
  t ? new Date(t * 1000).toLocaleTimeString([], { hour12: false }) : "";

export const pretty = (s: string | null | undefined): string => String(s || "").replace(/_/g, " ");
