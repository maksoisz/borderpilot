"""Local demo server (standard library only).

    python -m borderpilot.server                 # http://127.0.0.1:8000
    python -m borderpilot.server --port 9000 --live-fx

Single-user sandbox for demos: binds to localhost by default and has no login. In production the approval endpoint
would sit behind strong customer authentication (passkey / banking app confirmation)."""
from __future__ import annotations

import argparse
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .app import build_app, make_llm_client, new_student_session
from .drills import run_drills
from .fx import DATA_DIR
from .policy import PolicyDenied

WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"
MAX_BODY = 64 * 1024
SAMPLES = [
    ("01_harbourview_legit.txt", "Tuition, UK (genuine)"),
    ("06_southbay_cny_legit.txt", "Tuition, China (genuine)"),
    ("07_rheinland_legit.txt", "Fees, Germany (genuine)"),
    ("02_harbourview_account_swapped.txt", "“Our bank details changed”"),
    ("05_prompt_injection.txt", "Invoice that orders the AI"),
    ("03_lookalike_domain_urgent.txt", "Look-alike sender"),
    ("04_unknown_payee_crypto.txt", "Crypto “discount”"),
]


class Demo:
    def __init__(self, live_fx: bool):
        self.live_fx = live_fx
        self.lock = threading.Lock()
        self.client, self.model = make_llm_client()
        self.reset()

    def reset(self):
        self.app = build_app(live_fx=self.live_fx)
        self.session = new_student_session(self.app)

    def meta(self) -> dict:
        return {"planner": f"Claude ({self.model})" if self.client else "Deterministic planner (offline)",
                "fx": "ECB reference rates" if self.live_fx else "Sample rates (indicative)"}

    def run(self, text: str) -> dict:
        doc = self.session.add_document(text)
        if self.client:
            return self.app.run_llm(self.session, doc, self.client, self.model)
        return self.app.run(self.session, doc)


DEMO: Demo | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "BorderPilotDemo/0.1"

    def log_message(self, fmt, *args):  # quieter console
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, default=str).encode(), "application/json; charset=utf-8")

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request too large")
        if n and "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ValueError("expected application/json")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        d = DEMO
        if self.path in ("/", "/index.html"):
            return self._send(200, WEB.read_bytes(), "text/html; charset=utf-8")
        with d.lock:
            if self.path == "/api/samples":
                return self._json([{"id": f, "label": label, "text": (DATA_DIR / "invoices" / f).read_text()}
                                   for f, label in SAMPLES])
            if self.path == "/api/state":
                return self._json({"meta": d.meta(), "state": d.app.state(d.session)})
            if self.path == "/api/audit":
                ok, bad = d.app.ledger.verify_audit()
                return self._json({"chain_ok": ok, "first_bad_seq": bad, "rows": d.app.ledger.audit_rows()[-60:]})
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        d = DEMO
        try:
            body = self._body()
        except Exception as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        with d.lock:
            try:
                if self.path == "/api/run":
                    text = str(body.get("text", ""))[:20000]
                    if not text.strip():
                        return self._json({"error": "Paste an invoice or pick a sample first."}, 400)
                    return self._json({"meta": d.meta(), "state": d.run(text)})
                if self.path == "/api/approve":
                    d.app.approve(d.session, str(body.get("plan_hash", "")), bool(body.get("step_up")))
                    return self._json({"meta": d.meta(), "state": d.app.state(d.session)})
                if self.path == "/api/reset":
                    d.reset()
                    return self._json({"meta": d.meta(), "state": d.app.state(d.session)})
                if self.path == "/api/drills":
                    return self._json({"drills": run_drills()})
            except PolicyDenied as e:
                return self._json({"denied": e.code, "message": e.message, "meta": d.meta(),
                                   "state": d.app.state(d.session)}, 409)
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)


def main(argv=None):
    global DEMO
    ap = argparse.ArgumentParser(description="BorderPilot local demo server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--live-fx", action="store_true", help="use ECB reference rates (needs internet)")
    a = ap.parse_args(argv)
    DEMO = Demo(a.live_fx)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"BorderPilot sandbox running on http://{a.host}:{a.port}  ({DEMO.meta()['planner']}; {DEMO.meta()['fx']})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
