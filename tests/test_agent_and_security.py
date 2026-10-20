"""Agent behaviour, the Claude tool-use loop (with a fake client), every security drill, the HTTP server and the
evaluation thresholds."""
import json
import threading
import unittest
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

from borderpilot import server as srv
from borderpilot.app import build_app, new_student_session
from borderpilot.common import FixedClock
from borderpilot.drills import DRILLS, _FakeClient, _tool
from borderpilot.evaluate import evaluate
from borderpilot.fx import DATA_DIR
from borderpilot.policy import PolicyDenied

T0 = datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)


def sample(name):
    return (DATA_DIR / "invoices" / name).read_text()


def fresh():
    clock = FixedClock(T0)
    app = build_app(clock=clock)
    return app, new_student_session(app), clock


class AgentTests(unittest.TestCase):
    def test_end_to_end_legit_payment(self):
        app, s, _ = fresh()
        st = app.run(s, s.add_document(sample("01_harbourview_legit.txt")))
        self.assertEqual(st["status"], "AWAITING_APPROVAL")
        self.assertEqual([t["tool"] for t in st["trace"]],
                         ["read_invoice", "verify_payee", "get_fx_quote", "compare_routes", "forecast_budget",
                          "propose_payment"])
        before = app.ledger.balance(s.funding_account_id)
        app.approve(s, st["plan"]["plan_hash"])
        self.assertEqual(s.status, "EXECUTED")
        self.assertEqual(before - app.ledger.balance(s.funding_account_id), s.plan.src_total_minor)
        pay = app.ledger.payments()[0]
        self.assertEqual((pay["dst_amount_minor"], pay["dst_ccy"]), (925000, "GBP"))
        self.assertEqual(pay["beneficiary_account"], "GB82WEST12345698765432")
        self.assertEqual(app.ledger.verify_audit(), (True, None))

    def test_blocked_invoice_never_reaches_proposal(self):
        app, s, _ = fresh()
        st = app.run(s, s.add_document(sample("02_harbourview_account_swapped.txt")))
        self.assertEqual(st["status"], "BLOCKED")
        self.assertIsNone(st["plan"])
        self.assertNotIn("propose_payment", [t["tool"] for t in st["trace"]])

    def test_agent_cannot_execute_even_with_valid_token(self):
        app, s, _ = fresh()
        app.run(s, s.add_document(sample("01_harbourview_legit.txt")))
        token = app.approvals.issue(plan_hash=s.plan.hash(), user_id=s.user_id)
        with self.assertRaises(PolicyDenied) as cm:
            app.call_tool(s, "execute_payment", {"approval_token": token}, actor="agent")
        self.assertEqual(cm.exception.code, "TOOL_NOT_ALLOWED")

    def test_unexpected_arguments_rejected(self):
        app, s, _ = fresh()
        with self.assertRaises(PolicyDenied) as cm:
            app.call_tool(s, "verify_payee", {"override": True})
        self.assertEqual(cm.exception.code, "BAD_ARGUMENTS")

    def test_llm_loop_happy_path(self):
        app, s, _ = fresh()
        doc = s.add_document(sample("07_rheinland_legit.txt"))
        client = _FakeClient([[_tool("read_invoice", 1, doc_id=doc)], [_tool("verify_payee", 2)],
                              [_tool("get_fx_quote", 3)], [_tool("compare_routes", 4)],
                              [_tool("forecast_budget", 5)], [_tool("propose_payment", 6)],
                              [{"type": "text", "text": "Your plan is ready; please review and approve it."}]])
        st = app.run_llm(s, doc, client, "fake-model")
        self.assertEqual(st["status"], "AWAITING_APPROVAL")
        self.assertTrue(st["planner"].startswith("llm:"))
        tool_names = [t["name"] for t in client.calls[0]["tools"]]
        self.assertNotIn("execute_payment", tool_names)
        self.assertIn("untrusted", client.calls[0]["system"])

    def test_llm_ungrounded_summary_is_withheld(self):
        app, s, _ = fresh()
        doc = s.add_document(sample("07_rheinland_legit.txt"))
        client = _FakeClient([[_tool("read_invoice", 1, doc_id=doc)], [_tool("verify_payee", 2)],
                              [_tool("get_fx_quote", 3)], [_tool("compare_routes", 4)], [_tool("propose_payment", 5)],
                              [{"type": "text", "text": "Done! You saved 777,777 PLN."}]])
        st = app.run_llm(s, doc, client, "fake-model")
        self.assertNotIn("777,777", st["message"])
        self.assertIn("withheld", st["message"])

    def test_llm_step_limit(self):
        app, s, _ = fresh()
        doc = s.add_document(sample("07_rheinland_legit.txt"))
        client = _FakeClient([[_tool("verify_payee", i)] for i in range(20)])
        st = app.run_llm(s, doc, client, "fake-model", max_steps=3)
        self.assertIn("step limit", st["message"])


class SecurityDrillTests(unittest.TestCase):
    def test_every_drill(self):
        for did, attack, fn in DRILLS:
            with self.subTest(drill=did, attack=attack):
                passed, code, control = fn()
                self.assertTrue(passed, f"{did}: outcome {code}")


class EvaluationTests(unittest.TestCase):
    def test_headline_metrics(self):
        m = evaluate()["metrics"]
        self.assertEqual(m["task_completion_rate"], "12/12")
        self.assertEqual(m["false_alarm_on_registered_legit"], "0/12")
        self.assertTrue(m["attacker_payouts_cautious_user"].startswith("0/"))
        self.assertTrue(m["attacker_payouts_careless_user"].startswith("0/"))
        a, b = m["security_drills_passed"].split("/")
        self.assertEqual(a, b)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        srv.DEMO = srv.Demo(live_fx=False)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path, method="POST" if body is not None else "GET",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_page_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
            self.assertIn(b"BorderPilot", r.read())

    def test_run_approve_audit(self):
        self.call("/api/reset", {})
        code, res = self.call("/api/run", {"text": sample("01_harbourview_legit.txt")})
        self.assertEqual((code, res["state"]["status"]), (200, "AWAITING_APPROVAL"))
        h = res["state"]["plan"]["plan_hash"]
        code, res = self.call("/api/approve", {"plan_hash": "0" * 64})
        self.assertEqual((code, res["denied"]), (409, "APPROVAL_PLAN_MISMATCH"))
        code, res = self.call("/api/approve", {"plan_hash": h})
        self.assertEqual(res["state"]["status"], "EXECUTED")
        code, audit = self.call("/api/audit")
        self.assertTrue(audit["chain_ok"])

    def test_rejects_oversized_and_empty(self):
        code, _ = self.call("/api/run", {"text": "x" * 70000})
        self.assertEqual(code, 400)
        code, _ = self.call("/api/run", {"text": "   "})
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
