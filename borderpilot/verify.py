"""Beneficiary verification against a registry of OFFICIAL payment instructions (invoice-fraud defence).

Additive, explainable risk score (0-100). Every point comes from a named rule with a human-readable reason.
>= 70 BLOCKED (cannot be paid, even with step-up) | 30-69 REVIEW (needs step-up approval) | < 30 VERIFIED."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

from .fx import DATA_DIR
from .invoice import Invoice
from .money import from_minor

BLOCK_AT, REVIEW_AT = 70, 30

RULE_POINTS = {
    "UNKNOWN_PAYEE": 60, "PAYEE_IMPERSONATION": 40, "ACCOUNT_MISMATCH": 80, "BIC_MISMATCH": 40,
    "UNEXPECTED_CURRENCY": 20, "AMOUNT_OUTSIDE_TYPICAL_RANGE": 15, "LOOKALIKE_DOMAIN": 50,
    "SENDER_DOMAIN_NOT_OFFICIAL": 30, "INVALID_IBAN_CHECKSUM": 50, "PROMPT_INJECTION_SUSPECTED": 70,
    "UNUSUAL_PAYMENT_METHOD": 50, "URGENCY_PRESSURE": 15, "CONFLICTING_FIELD": 40, "EXTRACTION_DISAGREEMENT": 40,
}


def norm_account(a: str | None) -> str:
    return re.sub(r"\s+", "", a or "").upper()


def looks_like_iban(a: str) -> bool:
    return bool(re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", a))


def iban_valid(iban: str) -> bool:
    s = norm_account(iban)
    if not looks_like_iban(s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def _norm_name(n: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", n.lower())).strip()


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _norm_name(a), _norm_name(b)).ratio()


class Registry:
    def __init__(self, path=None):
        self.institutions = json.loads(Path(path or DATA_DIR / "registry.json").read_text())["institutions"]

    def match_payee(self, name: str):
        best, score = None, 0.0
        for inst in self.institutions:
            for cand in [inst["name"], *inst.get("aliases", [])]:
                s = similarity(name, cand)
                if s > score:
                    best, score = inst, s
        return (best, score) if score >= 0.85 else (None, score)

    def is_official_account(self, account: str | None) -> bool:
        acct = norm_account(account)
        return any(norm_account(a["account"]) == acct for i in self.institutions for a in i["accounts"])


@dataclass
class VerificationResult:
    status: str                       # VERIFIED | REVIEW | BLOCKED
    risk_score: int
    reasons: list[dict] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)
    institution_id: str | None = None
    country: str | None = None

    def to_dict(self) -> dict:
        return {"status": self.status, "risk_score": self.risk_score, "reasons": self.reasons,
                "passed": self.passed, "institution_id": self.institution_id, "country": self.country}


def verify_beneficiary(inv: Invoice, registry: Registry) -> VerificationResult:
    reasons: list[dict] = []
    passed: list[str] = []

    def add(code: str, msg: str):
        reasons.append({"code": code, "message": msg, "points": RULE_POINTS[code]})

    inst, name_score = registry.match_payee(inv.payee or "")
    acct = norm_account(inv.account)

    if inst is None:
        add("UNKNOWN_PAYEE", "Payee is not in the registry of verified institutions; confirm the payment details on "
            "the institution's official website or by phone before paying.")
        if name_score >= 0.6:
            add("PAYEE_IMPERSONATION", "Payee name closely imitates a registered institution but does not match it.")
    else:
        passed.append("PAYEE_IN_REGISTRY")
        official = {norm_account(a["account"]): a for a in inst["accounts"]}
        if acct in official:
            passed.append("ACCOUNT_MATCHES_OFFICIAL")
            if inv.bic and official[acct].get("bic") and inv.bic != official[acct]["bic"]:
                add("BIC_MISMATCH", "BIC on the invoice differs from the official BIC for this account.")
        else:
            add("ACCOUNT_MISMATCH", f"Account on the invoice is not an official account of {inst['name']} "
                "(classic invoice-fraud pattern: 'our bank details have changed').")
        if inv.currency and inv.currency not in {a["currency"] for a in inst["accounts"]}:
            add("UNEXPECTED_CURRENCY", f"{inst['name']} does not normally invoice in {inv.currency}.")
        rng = inst.get("typical_amount", {}).get(inv.currency or "")
        if rng and inv.amount_minor is not None:
            amt = from_minor(inv.amount_minor, inv.currency)
            if not rng[0] <= amt <= rng[1]:
                add("AMOUNT_OUTSIDE_TYPICAL_RANGE", "Amount is outside the typical range for this institution.")
        dom = inv.sender_domain
        if dom:
            domains = inst.get("domains", [])
            if any(dom == d or dom.endswith("." + d) for d in domains):
                passed.append("SENDER_DOMAIN_OFFICIAL")
            elif any(similarity(dom, d) >= 0.8 for d in domains):
                add("LOOKALIKE_DOMAIN", f"Sender domain '{dom}' imitates an official domain.")
            else:
                add("SENDER_DOMAIN_NOT_OFFICIAL", f"Sender domain '{dom}' is not an official domain.")

    if acct and looks_like_iban(acct):
        if iban_valid(acct):
            passed.append("IBAN_CHECKSUM_OK")
        else:
            add("INVALID_IBAN_CHECKSUM", "IBAN fails the ISO 13616 mod-97 checksum (typo or forged number).")

    flag_msgs = {"PROMPT_INJECTION_SUSPECTED": "Document contains instruction-like text aimed at an AI agent; "
                                               "it was ignored and the payment is blocked.",
                 "UNUSUAL_PAYMENT_METHOD": "Document asks for an unusual payment method (crypto, gift cards, cash "
                                           "transfer services).",
                 "URGENCY_PRESSURE": "Document uses pressure or urgency language."}
    seen = set()
    for fl in inv.flags:
        code = fl.split(":")[0]
        if code in flag_msgs:
            add(code, flag_msgs[code])
        elif code in ("CONFLICTING_FIELD", "EXTRACTION_DISAGREEMENT") and code not in seen:
            seen.add(code)
            add(code, f"Inconsistent data in the document ({fl}).")

    score = min(100, sum(r["points"] for r in reasons))
    status = "BLOCKED" if score >= BLOCK_AT else "REVIEW" if score >= REVIEW_AT else "VERIFIED"
    return VerificationResult(status, score, reasons, passed, inst["id"] if inst else None,
                              inst["country"] if inst else None)
