"""TripWire command line.

    python -m tripwire serve [--port 8765] [--open]   interactive security console
    python -m tripwire demo                           scripted end-to-end story (terminal), event mode
    python -m tripwire invoice-demo                   PRD demo script: invoice task, replay vs protected
    python -m tripwire attack-demo                    every attack scenario, strict vs baseline
    python -m tripwire --demo / --attack-demo         legacy shortcuts
"""
from __future__ import annotations

import argparse
import os
import sys

from .session import Session

# Windows consoles may not be UTF-8; never crash on output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass


def _fmt(d) -> str:
    line = f"[{d.outcome:<8}] {d.message_type:<18} {d.sender_id:<18} {d.code}"
    if d.would_fail:
        line += f" (would also fail: {d.would_fail})"
    if d.handled:
        line += f" | {d.handled}"
    if d.action is not None:
        line += "\n" + " " * 11 + "-> " + _fmt(d.action)
    return line


def _threshold() -> float:
    return float(os.getenv("TRIPWIRE_THRESHOLD", "70"))


def run_demo(args: argparse.Namespace) -> int:
    s = Session(_threshold(), attack_delay_s=0, recovery_code=os.getenv("TRIPWIRE_RECOVERY_CODE"))
    if getattr(args, "firewall_on", False) or os.getenv("TRIPWIRE_FIREWALL", "").lower() in {"1", "true", "on"}:
        s.set_firewall("BLOCKING")
    print("TRIPWIRE :: scripted demo")
    print(f"threshold={s.threshold:g}  firewall={s.firewall.mode}  profile={s.gateway.profile}\n")
    print("1) Agent 1 replays the deterministic 'incident' event stream:")
    for _ in range(6):
        r = s.stream_step("incident")
        print(f"   {r['event']:<22} score={s.monitor.model.score:6.2f}  {_fmt(r['decision'])}")
    print("\n2) Adversary attacks (strict profile):")
    for sid in ("forged_sender", "tamper", "replay", "unauthorized_action"):
        for row in s.run_attack(sid):
            print(f"   {sid:<20} {row['outcome']:<8} {row['code']:<20} {row['reason'][:60]}")
    print(f"\n3) Firewall now: {s.firewall.mode} ({s.firewall.reason})")
    if s.firewall.mode == "NORMAL":
        s.set_firewall("BLOCKING")
        print("   operator engaged kill switch -> BLOCKING")
    d = s.send_alert()
    print("   Agent 1 attempts the protected alert while engaged:\n   " + _fmt(d))
    print(f"   outbox deliveries still: {s.outbox.delivered_count}")
    print(f"\n4) Authorized recovery with operator code -> ", end="")
    s.recover(s.recovery_code)
    print(s.firewall.mode)
    m = s.metrics()
    print(f"\nEmails simulated-delivered: {m['emails_delivered']} | denied email attempts: {m['email_denied']}"
          f" | attacks: {m['attack_attempts']} attempted, {m['attack_passed']} passed")
    print(f"Audit chain: {s.verify_audit()}")
    print(f"Outbox file: {s.outbox.path}")
    return 0


def _tool_line(row) -> str:
    stamp = {"ALLOW": "ALLOW   ", "BLOCK": "BLOCK   ", "APPROVAL": "APPROVAL"}.get(row["decision"], row["decision"])
    ran = "executed" if row.get("executed") else "not executed"
    return f"   [{stamp}] {row['action']:<27} {row['code']:<22} {ran:<13} source={row['source']['context']}"


def _report_lines(report) -> str:
    return (f"   severity {report['severity'].upper()} (attempted {report['attempted_severity'].upper()}), "
            f"{report['containment']}\n"
            f"   sensitive records: {report['sensitive_records_exposed']} exposed, "
            f"{report['sensitive_records_protected']} protected | canaries: {report['canaries_exposed']} exposed, "
            f"{report['canaries_protected']} protected\n"
            f"   external destinations reached: {', '.join(report['external_destinations_reached']) or 'none'}")


def run_invoice_demo(args: argparse.Namespace) -> int:
    """The PRD section 15 script, in the terminal, with the three agents named."""
    s = Session(_threshold(), attack_delay_s=0, recovery_code=os.getenv("TRIPWIRE_RECOVERY_CODE"))
    scenario = "footer_injection"
    print("TRIPWIRE :: invoice demo (PRD script) - constrain -> enforce -> prove")
    print("Agent 1 intake agent | Agent 2 policy validator | Agent 3 red team | all traffic through the gateway\n")
    print("1) Scenario: Invoice Footer Injection (Agent 3 planted a sentence in the invoice footer)")
    task = s.start_task(scenario)
    view = s.task_view(task.task_id)
    print(f"2) Task assigned: \"{view['goal']}\"  ->  task {view['task_id']}")
    m = view["manifest"]
    print(f"3) Signed manifest {view['manifest_hash'][:16]}...")
    print(f"   allowed tools : {', '.join(m['allowed_tools'])}")
    print(f"   forbidden     : {', '.join(m['forbidden_tools'])}")
    print(f"   data scope    : {', '.join(m['allowed_data'])} | limit INR {m['payment_limit_inr']:,} | "
          f"destinations: {', '.join(m['allowed_destinations'])}")
    for span in view["documents"][0]["spans"]:
        print(f"   untrusted instruction in the document: \"{span['text'][:90]}\"")
    replay = s.replay(scenario)
    print(f"\n4) Replay baseline ({replay['label'].lower()}; throwaway session, no policy checks):")
    for row in replay["baseline"]["timeline"]:
        if row["kind"] == "tool.decision":
            print(_tool_line(row))
    print("5) Baseline blast radius:")
    print(_report_lines(replay["baseline"]["report"]))
    print("\n6) Protected flow: Agent 1 reads the same document and proposes the same calls:")
    decisions = s.run_agent(task.task_id)
    view = s.task_view(task.task_id)
    for row in view["timeline"]:
        if row["kind"] == "tool.decision":
            print(_tool_line(row))
    blocked = next(d for d in decisions if d.tool["decision"] == "BLOCK")
    print(f"7) Why the gateway blocked {blocked.tool['tool']}: " + ", ".join(v["code"] for v in blocked.tool["violations"]))
    for v in blocked.tool["violations"]:
        print(f"     {v['code']:<22} {v['reason'][:110]}")
    alert = next((d.action for d in decisions if d.action is not None), None)
    if alert is not None and alert.email:
        print(f"   Agent 2: task risk crossed {s.threshold:g}; internal SOC email simulated to {', '.join(alert.email['to'])}")
    draft = (view["result"]["drafts"] or [None])[-1]
    if draft:
        print(f"8) Legitimate result: payment draft {draft['draft_id']} for INR {draft['amount_inr']:,.0f} "
              f"to {draft['vendor_name']} ({draft['status']})")
    print("9) Evidence ledger and protected blast radius:")
    print(_report_lines(view["report"]))
    counts = s.registry.executions
    print(f"   tool executions: export_customer_list={counts['export_customer_list']} "
          f"upload_external_file={counts['upload_external_file']} | firewall {s.firewall.mode} | "
          f"audit chain ok={s.verify_audit()['ok']}")
    return 0


def run_attack_demo(args: argparse.Namespace) -> int:
    print("TRIPWIRE :: attack matrix (same attacks, two gateway profiles)\n")
    from .attacks import SCENARIOS
    for profile in ("baseline", "strict"):
        s = Session(_threshold(), attack_delay_s=0, auto_lockdown=False)
        s.set_profile(profile)
        s.report_score(90)  # one legitimate alert so there is traffic to capture and replay
        print(f"--- profile: {profile.upper()}" + ("  (deliberately INSECURE comparison)" if profile == "baseline" else ""))
        for sc in SCENARIOS:
            if sc.id == "probe_while_blocked":
                continue
            rows = s.run_attack(sc.id)
            codes = sorted({r["code"] for r in rows})
            passed = sum(r["outcome"] == "ACCEPTED" for r in rows)
            emails = sum(r["email"] for r in rows)
            print(f"   {sc.id:<20} msgs={len(rows):<3} passed={passed:<3} emails={emails:<2} codes={','.join(codes)}")
        m = s.metrics()
        print(f"   => attack messages {m['attack_attempts']}, passed {m['attack_passed']}, "
              f"unauthorized emails {m['unauthorized_emails']}\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tripwire", description="TripWire multi-agent runtime defense")
    sub = parser.add_subparsers(dest="command")
    demo = sub.add_parser("demo", help="scripted end-to-end demo in the terminal")
    demo.add_argument("--firewall-on", action="store_true", help="start with the kill switch engaged")
    sub.add_parser("attack-demo", help="run every attack against strict and baseline profiles")
    sub.add_parser("invoice-demo", help="PRD demo script: invoice task, replay baseline vs protected")
    web = sub.add_parser("serve", help="launch the local security console")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    web.add_argument("--port", type=int, default=int(os.getenv("TRIPWIRE_PORT", "3000")))
    web.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    web.add_argument("--verbose", action="store_true", help="log every HTTP request")
    parser.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--attack-demo", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .server import run_server
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print("WARNING: binding to a non-loopback address exposes the unauthenticated demo controls.")
        session = Session(_threshold(), recovery_code=os.getenv("TRIPWIRE_RECOVERY_CODE"))
        run_server(session, args.host, args.port, args.open, quiet=not args.verbose)
        return 0
    if args.attack_demo or args.command == "attack-demo":
        return run_attack_demo(args)
    if args.command == "invoice-demo":
        return run_invoice_demo(args)
    if args.demo or args.command in (None, "demo"):
        return run_demo(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
