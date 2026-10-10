"use client";
import { useStore } from "@/lib/store";
import { toastState } from "@/lib/ui";

const HIDDEN = { msg: "", err: false, show: false };

export function Toaster() {
  const t = useStore(toastState, HIDDEN);
  return (
    <div id="toast" role="status" className={"toast" + (t.show ? " show" : "") + (t.err ? " err" : "")}>
      {t.msg}
    </div>
  );
}
