"""Invoice extraction. Document text is UNTRUSTED DATA: it is parsed and scanned, never obeyed."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from .common import mask_account, sha256_hex
from .money import to_minor

FIELD_KEYS = {
    "payee": {"payee", "beneficiary", "pay to", "account holder", "account name", "beneficiary name"},
    "account": {"iban", "account", "account number", "account no", "account no.", "bank account",
                "beneficiary account"},
    "bic": {"bic", "swift", "bic/swift", "swift/bic", "swift code"},
    "amount": {"amount due", "amount", "total due", "total", "total amount", "tuition fee", "fee"},
    "due": {"due date", "due", "deadline", "pay by", "payment due"},
    "reference": {"payment reference", "reference", "ref", "payment ref"},
    "sender": {"from", "sender", "issued by"},
}
KNOWN_CCY = {"EUR", "GBP", "USD", "PLN", "CNY", "CZK", "SEK", "CHF", "JPY", "CAD", "AUD", "NOK", "DKK", "HUF"}

INJECTION_PATTERNS = [re.compile(p, re.I | re.M) for p in [
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|messages)",
    r"disregard\s+.{0,40}(?:instructions|rules|polic(?:y|ies))",
    r"\b(?:system|developer)\s+(?:prompt|message|instruction)s?\b",
    r"\byou\s+are\s+now\b",
    r"\bas\s+an?\s+(?:ai|assistant|language\s+model)\b",
    r"^\s*(?:assistant|system|user)\s*:",
    r"</?\s*(?:system|assistant|tool|instructions?)\s*>",
    r"(?:change|update|replace|use)\s+(?:the\s+)?(?:beneficiary|payee|iban|account)\s+(?:to|with)",
    r"(?:do\s+not|don't|never)\s+(?:verify|check|alert|warn|ask|contact)",
    r"(?:approval|authori[sz]ation)\s+(?:has\s+been|is|was)\s+(?:already\s+)?(?:granted|given|obtained)",
    r"(?:execute|send|transfer|wire)\s+(?:the\s+)?(?:payment|funds|money)\s+(?:now|immediately|without)",
    r"\btool[_\s]?call\b|\bfunction[_\s]?call\b",
]]
URGENCY = re.compile(r"\b(?:urgent(?:ly)?|immediately|within\s+\d+\s*(?:hours|hrs)|final\s+notice|last\s+warning|"
                     r"today\s+only|asap)\b", re.I)
UNUSUAL_METHOD = re.compile(r"\b(?:gift\s*cards?|crypto(?:currency)?|bitcoin|btc|usdt|western\s+union|moneygram)\b", re.I)


@dataclass
class Invoice:
    payee: str | None = None
    account: str | None = None      # normalised: no spaces, upper-case
    bic: str | None = None
    amount_minor: int | None = None
    currency: str | None = None
    due_date: date | None = None
    reference: str | None = None
    sender_domain: str | None = None
    flags: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    text_hash: str = ""

    def public(self) -> dict:
        """PII-minimised view for logs, UI and the language model (account number masked)."""
        return {"payee": self.payee, "account_masked": mask_account(self.account or ""), "bic": self.bic,
                "amount_minor": self.amount_minor, "currency": self.currency,
                "due_date": self.due_date.isoformat() if self.due_date else None, "reference": self.reference,
                "sender_domain": self.sender_domain, "flags": list(self.flags), "missing": list(self.missing),
                "document_sha256": self.text_hash}


def scan_flags(text: str) -> list[str]:
    flags = []
    if any(p.search(text) for p in INJECTION_PATTERNS):
        flags.append("PROMPT_INJECTION_SUSPECTED")
    if URGENCY.search(text):
        flags.append("URGENCY_PRESSURE")
    if UNUSUAL_METHOD.search(text):
        flags.append("UNUSUAL_PAYMENT_METHOD")
    return flags


def sanitize_for_llm(text: str, max_chars: int = 4000) -> str:
    """Drop instruction-like lines, truncate, and fence the rest as untrusted data."""
    kept = [ln for ln in text.splitlines() if not any(p.search(ln) for p in INJECTION_PATTERNS)]
    body = "\n".join(kept)[:max_chars].replace("</untrusted_document>", "")
    return f"<untrusted_document>\n{body}\n</untrusted_document>"


def _normalize_number(s: str) -> Decimal | None:
    s = re.sub(r"[\s']", "", s.strip())
    if not s or not re.search(r"\d", s):
        return None
    if "," in s and "." in s:
        dec = "," if s.rfind(",") > s.rfind(".") else "."
        thou = "." if dec == "," else ","
        s = s.replace(thou, "").replace(dec, ".")
    elif "," in s or "." in s:
        sep = "," if "," in s else "."
        parts = s.split(sep)
        if len(parts) > 2:
            s = "".join(parts)
        elif len(parts[1]) == 3 and len(parts[0]) <= 3 and parts[0] != "0":
            s = "".join(parts)       # 9,250 -> thousands separator
        else:
            s = ".".join(parts)      # 9,25 / 9.25 -> decimal separator
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


def parse_amount(text: str) -> tuple[str, int] | None:
    m = re.search(r"\b([A-Z]{3})\s*([0-9][0-9\s.,']*)", text)
    if m and m.group(1) in KNOWN_CCY:
        ccy, num = m.group(1), m.group(2)
    else:
        m = re.search(r"([0-9][0-9\s.,']*?)\s*([A-Z]{3})\b", text)
        if not m or m.group(2) not in KNOWN_CCY:
            return None
        num, ccy = m.group(1), m.group(2)
    d = _normalize_number(num.rstrip(" .,"))
    if d is None or d <= 0:
        return None
    return ccy, to_minor(d, ccy)


def parse_date(text: str) -> date | None:
    t = text.strip()
    for f in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y", "%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(t[:20].strip(), f).date()
        except ValueError:
            continue
    m = re.search(r"\d{4}-\d{2}-\d{2}", t)
    return datetime.strptime(m.group(0), "%Y-%m-%d").date() if m else None


def _collect(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([^:\n]{2,40}):\s*(.+?)\s*$", line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1).strip().lower())
        for fld, names in FIELD_KEYS.items():
            if key in names:
                out.setdefault(fld, []).append(m.group(2))
    return out


def _acct(s: str | None) -> str | None:
    return re.sub(r"\s+", "", s).upper() if s else None


def extract_invoice(text: str, llm=None) -> Invoice:
    """Deterministic extraction; an optional LLM extraction is cross-checked, never trusted blindly."""
    raw = _collect(text)
    inv = Invoice(text_hash=sha256_hex(text), flags=scan_flags(text))
    for fld, vals in raw.items():
        if len({re.sub(r"\s+", "", v).lower() for v in vals}) > 1:
            inv.flags.append(f"CONFLICTING_FIELD:{fld}")

    def first(k):
        return raw[k][0] if raw.get(k) else None

    inv.payee, inv.account = first("payee"), _acct(first("account"))
    inv.bic = re.sub(r"\s+", "", first("bic")).upper() if first("bic") else None
    inv.reference = first("reference")
    if first("amount"):
        am = parse_amount(first("amount"))
        if am:
            inv.currency, inv.amount_minor = am
    inv.due_date = parse_date(first("due")) if first("due") else None
    if first("sender"):
        m = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", first("sender"))
        inv.sender_domain = m.group(1).lower() if m else None

    if llm is not None:
        try:
            ext = llm.extract_invoice_fields(sanitize_for_llm(text)) or {}
        except Exception:
            ext = {}
            inv.flags.append("LLM_EXTRACTION_FAILED")
        if ext:
            l_acct, l_ccy, l_amt = _acct(ext.get("account")), ext.get("currency"), ext.get("amount_minor")
            for name, mine, theirs in (("account", inv.account, l_acct), ("currency", inv.currency, l_ccy),
                                       ("amount", inv.amount_minor, l_amt)):
                if mine is not None and theirs is not None and mine != theirs:
                    inv.flags.append(f"EXTRACTION_DISAGREEMENT:{name}")
            for attr, val in (("payee", ext.get("payee")), ("bic", ext.get("bic")),
                              ("reference", ext.get("reference"))):
                if getattr(inv, attr) is None and val:
                    setattr(inv, attr, val)
                    inv.flags.append(f"LLM_ONLY:{attr}")

    inv.missing = [n for n, v in (("payee", inv.payee), ("account", inv.account), ("amount", inv.amount_minor),
                                  ("currency", inv.currency), ("due_date", inv.due_date)) if not v]
    return inv
