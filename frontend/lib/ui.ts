// Shared UI state: live firewall pill and the toast. Ported from tripwire/web/app.js.
import { createStore } from "./store";
import type { FirewallMode } from "./types";

export type PillMode = FirewallMode | "OFFLINE" | null;

export const firewallPill = createStore<PillMode>(null);

export function setFirewall(mode: PillMode): void {
  firewallPill.set(mode);
}

export interface ToastState {
  msg: string;
  err: boolean;
  show: boolean;
}

export const toastState = createStore<ToastState>({ msg: "", err: false, show: false });

let toastTimer: ReturnType<typeof setTimeout> | undefined;

export function toast(msg: string, err = false): void {
  toastState.set({ msg, err, show: true });
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastState.set({ msg, err, show: false }), err ? 4200 : 2600);
}
