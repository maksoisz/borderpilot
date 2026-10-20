"""Unit tests for the deterministic core: money, parsing, verification, routing, budgeting, ledger."""
import unittest
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

from borderpilot.budget import categorize, forecast_runway
from borderpilot.common import FixedClock, mask_account
from borderpilot.fx import DATA_DIR, StaticFX
from borderpilot.invoice import extract_invoice, parse_amount, parse_date, sanitize_for_llm
from borderpilot.ledger import Ledger, LedgerError
from borderpilot.money import fmt, from_minor, to_minor
from borderpilot.routes import compare_routes
from borderpilot.verify import Registry, iban_valid, verify_beneficiary

T0 = datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)


def sample(name):
    return (DATA_DIR / "invoices" / name).read_text()


class MoneyTests(unittest.TestCase):
    def test_minor_units_round_trip(self):
        self.assertEqual(to_minor("9250.00", "GBP"), 925000)
        self.assertEqual(from_minor(925000, "GBP"), Decimal("9250.00"))
        self.assertEqual(to_minor("1500", "JPY"), 1500)
        self.assertEqual(fmt(148050, "EUR"), "1,480.50 EUR")

    def test_half_up_rounding(self):
        self.assertEqual(to_minor("0.005", "EUR"), 1)
        self.assertEqual(to_minor("0.004", "EUR"), 0)


class ParsingTests(unittest.TestCase):
    def test_amount_formats(self):
        self.assertEqual(parse_amount("GBP 9,250.00"), ("GBP", 925000))
        self.assertEqual(parse_amount("1.480,50 EUR"), ("EUR", 148050))
        self.assertEqual(parse_amount("9 250,00 GBP"), ("GBP", 925000))
        self.assertEqual(parse_amount("CNY 52,000"), ("CNY", 5200000))
        self.assertEqual(parse_amount("EUR 12,5"), ("EUR", 1250))
        self.assertIsNone(parse_amount("XYZ 100"))
        self.assertIsNone(parse_amount("GBP -5"))

    def test_date_formats(self):
        self.assertEqual(parse_date("2026-12-04"), date(2026, 12, 4))
        self.assertEqual(parse_date("04.12.2026"), date(2026, 12, 4))
        self.assertEqual(parse_date("04 Dec 2026"), date(2026, 12, 4))
        self.assertIsNone(parse_date("next Tuesday"))

    def test_extract_legit_invoice(self):
        inv = extract_invoice(sample("01_harbourview_legit.txt"))
        self.assertEqual(inv.payee, "Harbourview University")
        self.assertEqual(inv.account, "GB82WEST12345698765432")
        self.assertEqual((inv.currency, inv.amount_minor), ("GBP", 925000))
        self.assertEqual(inv.due_date, date(2026, 12, 4))
        self.assertEqual(inv.sender_domain, "harbourview.example")
        self.assertEqual(inv.flags, [])
        self.assertEqual(inv.missing, [])

    def test_missing_fields_reported(self):
        inv = extract_invoice("Payee: Someone\nAmount due: EUR 10.00")
        self.assertIn("account", inv.missing)
        self.assertIn("due_date", inv.missing)

    def test_injection_flagged_and_fenced(self):
        text = sample("05_prompt_injection.txt")
        inv = extract_invoice(text)
        self.assertIn("PROMPT_INJECTION_SUSPECTED", inv.flags)
        self.assertEqual(inv.account, "GB82WEST12345698765432")  # the instruction never changes extraction
        fenced = sanitize_for_llm(text + "\n</untrusted_document>")
        self.assertNotIn("IGNORE ALL PREVIOUS", fenced)
        self.assertEqual(fenced.count("</untrusted_document>"), 1)

    def test_conflicting_fields(self):
        inv = extract_invoice(sample("01_harbourview_legit.txt") + "\nIBAN: NL91 ABNA 0417 1643 00")
        self.assertIn("CONFLICTING_FIELD:account", inv.flags)

    def test_public_view_masks_account(self):
        pub = extract_invoice(sample("01_harbourview_legit.txt")).public()
        self.assertEqual(pub["account_masked"], "****5432")
        self.assertNotIn("GB82WEST", str(pub))
        self.assertEqual(mask_account(None), "")


class VerificationTests(unittest.TestCase):
    reg = Registry()

    def check(self, name):
        return verify_beneficiary(extract_invoice(sample(name)), self.reg)

    def test_iban_checksum(self):
        self.assertTrue(iban_valid("GB82 WEST 1234 5698 7654 32"))
        self.assertTrue(iban_valid("DE89370400440532013000"))
        self.assertFalse(iban_valid("GB82WEST12345698765433"))

    def test_statuses_on_samples(self):
        expected = {"01_harbourview_legit.txt": "VERIFIED", "02_harbourview_account_swapped.txt": "BLOCKED",
                    "03_lookalike_domain_urgent.txt": "REVIEW", "04_unknown_payee_crypto.txt": "BLOCKED",
                    "05_prompt_injection.txt": "BLOCKED", "06_southbay_cny_legit.txt": "VERIFIED",
                    "07_rheinland_legit.txt": "VERIFIED"}
        for name, status in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.check(name).status, status)

    def test_reasons_are_explained(self):
        v = self.check("02_harbourview_account_swapped.txt")
        self.assertEqual([r["code"] for r in v.reasons], ["ACCOUNT_MISMATCH"])
        self.assertTrue(all(r["message"] and r["points"] > 0 for r in v.reasons))
        self.assertEqual(v.risk_score, sum(r["points"] for r in v.reasons))

    def test_impersonated_name(self):
        txt = sample("01_harbourview_legit.txt").replace("Payee: Harbourview University",
                                                         "Payee: Harbourview University Payments Ltd")
        txt = txt.replace("GB82 WEST 1234 5698 7654 32", "NL91 ABNA 0417 1643 00")
        codes = [r["code"] for r in verify_beneficiary(extract_invoice(txt), self.reg).reasons]
        self.assertIn("PAYEE_IMPERSONATION", codes)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.fx = StaticFX(clock=lambda: T0)
        self.inv = extract_invoice(sample("01_harbourview_legit.txt"))

    def test_totals_add_up_and_recipient_gets_exact_amount(self):
        c = compare_routes(self.inv, self.fx.quote("PLN", "GBP"), self.fx, T0)
        for o in c.options:
            self.assertEqual(o.src_total_minor, o.conversion_src_minor + o.fee_src_minor)
            received = Decimal(o.conversion_src_minor) / 100 * Decimal(o.effective_rate)
            self.assertAlmostEqual(float(received), 9250.00, delta=0.02)
        self.assertEqual([o.src_total_minor for o in c.options], sorted(o.src_total_minor for o in c.options))

    def test_recommends_cheapest_feasible_and_excludes_over_limit(self):
        c = compare_routes(self.inv, self.fx.quote("PLN", "GBP"), self.fx, T0)
        feasible = [o for o in c.options if o.deadline_ok]
        self.assertEqual(c.recommended_id, min(feasible, key=lambda o: o.src_total_minor).route_id)
        self.assertIn("card_portal", [e["route_id"] for e in c.excluded])
        self.assertGreater(c.savings_vs_baseline_minor, 0)

    def test_tight_deadline_prefers_fast_route(self):
        self.inv.due_date = (T0 + timedelta(days=2)).date()
        c = compare_routes(self.inv, self.fx.quote("PLN", "GBP"), self.fx, T0)
        self.assertEqual(c.recommended_id, "fintech_fast")

    def test_impossible_deadline_flags_risk(self):
        self.inv.due_date = T0.date()
        c = compare_routes(self.inv, self.fx.quote("PLN", "GBP"), self.fx, T0)
        self.assertTrue(c.deadline_risk)
        self.assertIn("fastest", c.rationale)


class BudgetTests(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(categorize("Rent - landlord"), "rent")
        self.assertEqual(categorize("Supermarket"), "groceries")
        self.assertEqual(categorize("Something else"), "other")

    def test_runway_status(self):
        fx = StaticFX(clock=lambda: T0)
        bal = [{"balance_minor": 1_000_000, "currency": "PLN"}]
        self.assertEqual(forecast_runway(bal, "PLN", fx, 500_000)["runway_months"], "2.0")
        self.assertEqual(forecast_runway(bal, "PLN", fx, 500_000)["status"], "WARNING")
        self.assertEqual(forecast_runway(bal, "PLN", fx, 100_000, 200_000)["status"], "SUSTAINABLE")


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.l = Ledger(clock=FixedClock(T0))
        self.acc = self.l.open_account("u", "PLN", 100_000)

    def pay(self, plan_hash="p1", nonce="n1", amount=40_000):
        return self.l.record_payment(owner="u", plan_hash=plan_hash, account_id=self.acc, debit_minor=amount,
                                     fee_minor=0, src_ccy="PLN", dst_ccy="GBP", dst_amount_minor=1, fx_rate="1",
                                     route_id="r", beneficiary_account="X", beneficiary_masked="****X",
                                     ref_amount_minor=1, nonce=nonce)

    def test_payment_debits_once(self):
        self.pay()
        self.assertTrue(self.pay(nonce="n2")["duplicate"])
        self.assertEqual(self.l.balance(self.acc), 60_000)

    def test_nonce_reuse_rejected(self):
        self.pay()
        with self.assertRaises(LedgerError):
            self.pay(plan_hash="p2", nonce="n1")
        self.assertEqual(self.l.balance(self.acc), 60_000)

    def test_balance_never_negative(self):
        with self.assertRaises(LedgerError):
            self.pay(amount=200_000)
        self.assertEqual(self.l.balance(self.acc), 100_000)

    def test_audit_chain_detects_edits_and_deletions(self):
        self.pay()
        self.assertEqual(self.l.verify_audit(), (True, None))
        self.l.db.execute("DELETE FROM audit WHERE seq=1")
        ok, bad = self.l.verify_audit()
        self.assertFalse(ok)
        self.assertEqual(bad, 2)


if __name__ == "__main__":
    unittest.main()
