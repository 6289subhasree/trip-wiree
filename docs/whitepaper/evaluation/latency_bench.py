"""Gateway decision latency, as the gateway records it on every decision (``Decision.latency_ms``).

    python docs/whitepaper/evaluation/latency_bench.py

Standard library only. Prints the median, 95th and 99th percentile and the slowest of 1,000
decisions of each kind. A fake clock advances one second per message so the rate limiter and the
freshness window never interfere; the time measured is real.
"""
import platform
import statistics
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tripwire.session import Session  # noqa: E402
from tests.helpers import FakeClock, doc_evidence, open_invoice_task, proposal, task_evidence  # noqa: E402

N = 1000


def report(label: str, values: list) -> None:
    values = sorted(values)

    def pct(q: float) -> float:
        return values[min(len(values) - 1, int(q * len(values)))]

    print(f"{label:<42} n={len(values):<5} median {statistics.median(values):.3f} ms   p95 {pct(0.95):.3f} ms   "
          f"p99 {pct(0.99):.3f} ms   slowest {values[-1]:.3f} ms")


def main() -> int:
    clock = FakeClock()
    with tempfile.TemporaryDirectory() as tmp:
        s = Session(data_dir=tmp, attack_delay_s=0, auto_lockdown=False, clock=clock)
        telemetry, allowed, blocked = [], [], []
        for _ in range(N):
            clock.advance(1.0)
            d = s.report_score(40)
            assert d.outcome == "ACCEPTED", d.code
            telemetry.append(d.latency_ms)
        task = open_invoice_task(s, ttl_s=10 * N)
        for _ in range(N):
            clock.advance(1.0)
            d = s.tool_call(task.task_id, proposal("extract_invoice_fields", {"invoice_id": "INV-1042"},
                                                   evidence=task_evidence(task)))
            assert (d.outcome, d.code) == ("ACCEPTED", "OK"), d.code
            allowed.append(d.latency_ms)
            clock.advance(1.0)
            d = s.tool_call(task.task_id, proposal("export_customer_list", evidence=doc_evidence(),
                                                   destination="vendor-check.invalid"))
            assert (d.outcome, d.code) == ("REJECTED", "TOOL_FORBIDDEN"), d.code
            blocked.append(d.latency_ms)
        s.stop_attacks()
    print(f"Python {platform.python_version()} on {platform.system()} {platform.release()}")
    report("telemetry envelope, accepted", telemetry)
    report("tool request, allowed (tool runs)", allowed)
    report("tool request, blocked (four violations)", blocked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
