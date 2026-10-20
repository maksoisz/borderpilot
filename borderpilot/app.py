"""Wiring: build a sandbox app and a sample student session."""
from __future__ import annotations

import json
import os
from decimal import Decimal
from pathlib import Path

from .agent import BorderPilot, Session
from .common import utcnow
from .fx import DATA_DIR, FrankfurterFX, StaticFX
from .ledger import Ledger
from .llm import TemplateLLM
from .money import to_minor
from .policy import ApprovalService, Limits, PolicyEngine
from .verify import Registry


def build_app(*, db_path: str = ":memory:", clock=utcnow, live_fx: bool = False, llm=None, limits: Limits | None = None,
              secret: bytes | None = None, fees_path=None) -> BorderPilot:
    static = StaticFX(clock=clock)
    fx = FrankfurterFX(static, clock=clock) if live_fx else static
    ledger = Ledger(db_path, clock=clock)
    approvals = ApprovalService(secret, clock=clock)
    policy = PolicyEngine(approvals, limits or Limits(), ledger, fx, clock=clock)
    return BorderPilot(ledger=ledger, fx=fx, registry=Registry(), approvals=approvals, policy=policy,
                       llm=llm or TemplateLLM(), clock=clock, fees_path=fees_path)


def new_student_session(app: BorderPilot, profile_path=None, balance_overrides: dict | None = None,
                        user_id: str | None = None) -> Session:
    prof = json.loads(Path(profile_path or DATA_DIR / "student_profile.json").read_text())
    uid = user_id or prof["user_id"]
    funding = None
    for a in prof["accounts"]:
        bal = (balance_overrides or {}).get(a["currency"], a["balance"])
        acc_id = app.ledger.open_account(uid, a["currency"], to_minor(Decimal(str(bal)), a["currency"]))
        if a.get("funding"):
            funding = acc_id
    tx = [{"date": t["date"], "description": t["description"], "currency": t["currency"],
           "amount_minor": to_minor(Decimal(str(t["amount"])), t["currency"])} for t in prof["transactions"]]
    return Session(user_id=uid, funding_account_id=funding, home_ccy=prof["home_ccy"],
                   monthly_income_minor=to_minor(Decimal(str(prof["monthly_income"])), prof["home_ccy"]),
                   transactions=tx)


def make_llm_client():
    """Return (client, model) when BORDERPILOT_LLM=anthropic and the SDK + API key are present, else (None, None)."""
    if os.environ.get("BORDERPILOT_LLM", "").lower() != "anthropic" or not os.environ.get("ANTHROPIC_API_KEY"):
        return None, None
    try:
        import anthropic  # noqa: PLC0415
    except ImportError:
        return None, None
    from .llm import DEFAULT_MODEL  # noqa: PLC0415
    return anthropic.Anthropic(), os.environ.get("BORDERPILOT_MODEL", DEFAULT_MODEL)
