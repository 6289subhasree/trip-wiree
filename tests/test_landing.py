"""Landing page: "/" serves the built Next.js export when present and the classic page when not."""
import json
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tripwire.server import LANDING_DIR, WEB_DIR, landing_asset, make_handler
from tests.helpers import make_session

BUILT_PAGE = b'<!doctype html><title>built landing</title><script src="/_next/static/chunks/app.js"></script>'
CLASSIC_NEEDLE = b"Your Gateway Between"
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
       "script-src 'self' 'unsafe-inline'; media-src 'self' https://d8j0ntlcm91z4.cloudfront.net; frame-ancestors 'none'")


class LandingServer:
    """Mixin: a live server whose landing folder is a temp directory, built or missing."""
    built = True

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "out"
        if self.built:
            chunks = self.root / "_next" / "static" / "chunks"
            chunks.mkdir(parents=True)
            (self.root / "assets").mkdir()
            (self.root / "index.html").write_bytes(BUILT_PAGE)
            (chunks / "app.js").write_bytes(b"console.log(1)")
            (chunks / "app.css").write_bytes(b"body{}")
            (chunks / "secret.py").write_bytes(b"x = 1")
            (self.root / "assets" / "smoke.svg").write_bytes(b"<svg/>")
            (self.root / "404.html").write_bytes(b"not for serving")
            (Path(tmp.name) / "outside.js").write_bytes(b"outside the build folder")
        self.session = make_session(self, auto_lockdown=False)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          make_handler(self.session, quiet=True, landing_dir=self.root))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def get(self, path):
        try:
            with urlopen(self.base + path) as response:
                return response.status, response.headers, response.read()
        except HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def post(self, path, body, headers):
        req = Request(self.base + path, data=json.dumps(body).encode(), headers=headers)
        try:
            with urlopen(req) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_other_pages_are_unchanged(self):
        for path, name in (("/classic", "index.html"), ("/demo", "demo.html"), ("/arena", "arena.html"),
                           ("/evidence", "evidence.html")):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn("text/html", headers["Content-Type"])
            self.assertEqual(headers["Content-Security-Policy"], CSP)
            self.assertEqual(body, (WEB_DIR / name).read_bytes(), path)
        status, _, body = self.get("/console")
        self.assertEqual(status, 200)
        self.assertEqual(body, WEB_DIR.with_name("dashboard.html").read_bytes())
        self.assertIn(CLASSIC_NEEDLE, self.get("/classic")[2])


class BuiltLandingTests(LandingServer, unittest.TestCase):
    def test_root_serves_the_built_page_with_the_same_security_headers(self):
        for path in ("/", "/index.html"):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertEqual(body, BUILT_PAGE, path)
            self.assertIn("text/html", headers["Content-Type"])
            self.assertEqual(headers["Content-Security-Policy"], CSP)
            self.assertEqual(headers["X-Frame-Options"], "DENY")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_build_assets_are_served_with_their_types(self):
        for path, ctype, body in (("/_next/static/chunks/app.js", "text/javascript", b"console.log(1)"),
                                  ("/_next/static/chunks/app.css", "text/css", b"body{}"),
                                  ("/assets/smoke.svg", "image/svg+xml", b"<svg/>")):
            status, headers, got = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(ctype, headers["Content-Type"], path)
            self.assertEqual(got, body, path)
            self.assertEqual(headers["Content-Security-Policy"], CSP)

    def test_nothing_outside_the_asset_folders_is_reachable(self):
        for path in ("/_next/../outside.js", "/_next/static/../../../outside.js", "/_next/%2e%2e/outside.js",
                     "/assets/..%2f..%2foutside.js", "/_next/static/chunks/secret.py", "/_next/static/chunks/nope.js",
                     "/_next/static/chunks/", "/_next/", "/assets/../index.html", "/404.html", "/outside.js",
                     "/_next/static/chunks/app.js%00.py", "/_next/static%5Cchunks%5Capp.js", "/demo.html",
                     "/static/../server.py"):
            status, _, body = self.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"outside the build folder", body, path)
        self.assertIsNone(landing_asset(self.root, "/_next/static\\chunks\\app.js"))
        self.assertIsNone(landing_asset(self.root, "/_next/../outside.js"))
        self.assertIsNotNone(landing_asset(self.root, "/_next/static/chunks/app.js"))

    def test_landing_page_api_calls_still_pass_the_same_guard(self):
        ok = {"Content-Type": "application/json", "X-TripWire-Client": "dashboard"}
        status, data = self.post("/api/replay", {"scenario": "footer_injection"}, ok)
        self.assertEqual(status, 200)
        baseline, protected = data["replay"]["baseline"]["report"], data["replay"]["protected"]["report"]
        self.assertGreater(baseline["sensitive_records_exposed"], 0)
        self.assertEqual(protected["sensitive_records_exposed"], 0)
        self.assertEqual(protected["sensitive_records_protected"], baseline["sensitive_records_exposed"])
        for headers in ({"Content-Type": "application/json"}, dict(ok, Origin="http://evil.example")):
            status, _ = self.post("/api/replay", {"scenario": "footer_injection"}, headers)
            self.assertEqual(status, 403)
        status, _ = self.post("/api/replay", {"scenario": "footer_injection", "extra": 1}, ok)
        self.assertEqual(status, 400)
        status, _ = self.post("/api/replay", {"scenario": "footer_injection", "instruction": "x" * 5000}, ok)
        self.assertEqual(status, 413)
        _, _, body = self.get("/api/health")
        self.assertEqual(json.loads(body), {"ok": True, "firewall": "NORMAL"})


class FallbackLandingTests(LandingServer, unittest.TestCase):
    built = False

    def test_root_falls_back_to_the_classic_page(self):
        classic = (WEB_DIR / "index.html").read_bytes()
        self.assertIn(CLASSIC_NEEDLE, classic)
        for path in ("/", "/index.html"):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertEqual(body, classic, path)
            self.assertEqual(headers["Content-Security-Policy"], CSP)

    def test_build_assets_are_absent(self):
        for path in ("/_next/static/chunks/app.js", "/assets/smoke.svg"):
            self.assertEqual(self.get(path)[0], 404, path)


@unittest.skipUnless((LANDING_DIR / "index.html").is_file(), "vantage/out is not built")
class CommittedBuildTests(unittest.TestCase):
    """The build that ships in the repository: TripWire content, same-origin only."""

    def setUp(self):
        self.files = [f for f in LANDING_DIR.rglob("*") if f.is_file()]
        self.page = (LANDING_DIR / "index.html").read_text(encoding="utf-8")

    def test_page_is_about_tripwire_and_links_to_the_demo_pages(self):
        for needle in ("TripWire", "HELLCODE", "HackInverse 1.0",
                       'href="/demo"', 'href="/arena"', 'href="/evidence"'):
            self.assertIn(needle, self.page, needle)
        for stale in ("Vantage", "Dashboards", "Sign Up", "Get Started"):
            self.assertNotIn(stale, self.page, stale)

    def test_page_and_styles_load_nothing_external(self):
        self.assertIsNone(re.search(r'(src|href|poster|action)\s*=\s*"(https?:)?//(?!d8j0ntlcm91z4\.cloudfront\.net)', self.page))
        for f in self.files:
            text = f.read_text(encoding="utf-8", errors="ignore")
            if f.suffix in (".html", ".css"):
                self.assertIsNone(re.search(r"https?://(?!d8j0ntlcm91z4\.cloudfront\.net)", text), f.name)
                self.assertNotIn("@import", text, f.name)
                for url in re.findall(r"url\(([^)]*)\)", text):
                    self.assertTrue(url.strip("\"'").startswith(("/assets/", "/_next/", "#", "https://d8j0ntlcm91z4.cloudfront.net")), f"{f.name}: {url}")
            for needle in ("googleapis", "gstatic", "googletagmanager", "jsdelivr", "unpkg"):
                self.assertNotIn(needle, text, f"{f.name}: {needle}")

    def test_every_file_the_page_references_is_servable(self):
        refs = set(re.findall(r'(?:src|href)="(/?(?:_next|assets)/[^"]+)"', self.page))
        # Filter out anything with query parameters or fragments if that breaks the test
        refs = {r.split("?")[0].split("#")[0] for r in refs}
        for ref in refs:
            ref_path = ref if ref.startswith("/") else "/" + ref
            self.assertIsNotNone(landing_asset(LANDING_DIR, ref_path), ref)

    def test_posts_carry_the_client_header(self):
        scripts = "".join(f.read_text(encoding="utf-8", errors="ignore") for f in self.files if f.suffix == ".js")
        for needle in ("X-TripWire-Client", "/api/replay", "/api/health"):
            self.assertIn(needle, scripts, needle)


if __name__ == "__main__":
    unittest.main()
