import tempfile

from tripwire.session import Session

CODE = "TW-TEST-CODE"


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_session(testcase, **kwargs) -> Session:
    tmp = tempfile.TemporaryDirectory()
    testcase.addCleanup(tmp.cleanup)
    kwargs.setdefault("attack_delay_s", 0)
    kwargs.setdefault("recovery_code", CODE)
    s = Session(data_dir=tmp.name, **kwargs)
    testcase.addCleanup(s.stop_attacks)
    return s
