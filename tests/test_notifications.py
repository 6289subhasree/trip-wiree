"""The mock outbox: what it stores, and the desktop banner it may raise on macOS."""
import json
import os
import subprocess
import unittest
from unittest import mock

from tripwire import notifications
from tripwire.tools_gateway import CANARY_RE
from tripwire.vault import INVOICE_FOOTER_CANARY
from tests.helpers import make_session

HOSTILE = 'x" & do shell script "calc" & "\'; rm -rf ~ #\nsecond line \\'


def outside_literals(script: str):
    """The script with its string literals removed, and whether a literal was left open."""
    out, inside, i = [], False, 0
    while i < len(script):
        c = script[i]
        if inside and c == "\\":
            i += 2
            continue
        if c == '"':
            inside = not inside
        elif not inside:
            out.append(c)
        i += 1
    return "".join(out), inside


class DesktopBannerTests(unittest.TestCase):
    def test_delivery_never_starts_a_process_off_macos(self):
        s = make_session(self)
        with mock.patch.object(notifications.sys, "platform", "win32"), \
                mock.patch.object(os, "system", side_effect=AssertionError("shell used")), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("process started")):
            s.outbox.deliver_tool_email(task_id="T-1", correlation_id="c-1", to="x@y.invalid",
                                        body=f"Subject: {HOSTILE}\n\n{HOSTILE}", attachments=[], external=True)
        self.assertEqual(s.outbox.file_count(), 1)

    def test_macos_banner_is_one_argument_list_with_escaped_text_and_no_shell(self):
        with mock.patch.object(notifications.sys, "platform", "darwin"), \
                mock.patch.object(os, "system", side_effect=AssertionError("shell used")), \
                mock.patch.object(subprocess, "Popen") as popen:
            notifications._desktop_banner(HOSTILE, HOSTILE, HOSTILE)
        (argv,), kwargs = popen.call_args
        self.assertEqual(argv[:2], ["osascript", "-e"])
        self.assertEqual(len(argv), 3)
        self.assertFalse(kwargs.get("shell", False))
        script = argv[2]
        self.assertNotIn("\n", script)
        # all of the hostile text stays inside the three literals; the statement around them is untouched
        self.assertEqual(outside_literals(script),
                         ("display notification  with title  subtitle  sound name ", False))
        self.assertIn("do shell script", script)

    def test_text_literal_escapes_and_truncates(self):
        self.assertEqual(notifications._applescript_text('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(notifications._applescript_text("line\nbreak\ttab"), '"line break tab"')
        self.assertEqual(len(notifications._applescript_text("z" * 500)), 82)

    def test_a_missing_osascript_is_not_an_error(self):
        with mock.patch.object(notifications.sys, "platform", "darwin"), \
                mock.patch.object(subprocess, "Popen", side_effect=FileNotFoundError("osascript")):
            notifications._desktop_banner("body", "title", "x@y.invalid")


class StoredMailTests(unittest.TestCase):
    def test_agent_email_keeps_no_full_canary_in_subject_or_body(self):
        s = make_session(self)
        record = s.outbox.deliver_tool_email(
            task_id="T-1", correlation_id="c-1", to="x@y.invalid", attachments=[], external=True,
            body=f"Subject: ref {INVOICE_FOOTER_CANARY}\n\nPlease see {INVOICE_FOOTER_CANARY}.")
        stored = json.dumps([record, s.outbox.records, s.outbox.path.read_text(encoding="utf-8")])
        self.assertEqual(CANARY_RE.findall(stored), [])
        self.assertIn("TRIPWIRE-CANARY-*******-******-01", record["subject"])
        self.assertIn("TRIPWIRE-CANARY-*******-******-01", record["body"])
        self.assertEqual(record["canaries"], 2)   # still counted, from the unmasked text


if __name__ == "__main__":
    unittest.main()
