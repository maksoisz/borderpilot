"""Permission tiers, approval tokens and payment authorisation.

Design rule: the language model proposes, deterministic code disposes. Approval tokens can only be issued by the
human-facing ApprovalService, which is NOT exposed as an agent tool; every money-moving call is re-checked here."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from enum import IntEnum

from .common import utcnow
from .fx import LIVE_SOURCES


class Tier(IntEnum):
    READ = 0       # read-only analysis: parse, verify, quote, compare, forecast
    PROPOSE = 1    # build plans / drafts; no money moves
    EXECUTE = 2    # move money - only with a valid human approval bound to the exact plan


class PolicyDenied(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


@dataclass
class Limits:
    per_tx_ref_minor: int = 1_500_000      # 15,000 EUR equivalent per payment
    daily_ref_minor: int = 2_500_000       # 25,000 EUR equivalent per day
    max_payments_per_day: int = 3
    require_live_fx: bool = False          # True in production: indicative/static rates may not execute
    high_risk_countries: tuple = ()        # loaded from official sanctions / high-risk lists in production


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ApprovalService:
    """Human-facing approval. Signs (plan_hash, user, expiry, nonce, step-up) with HMAC-SHA256."""

    def __init__(self, secret: bytes | None = None, clock=utcnow, ttl_s: int = 600):
        self._secret = secret or secrets.token_bytes(32)
        self.clock, self.ttl_s = clock, ttl_s

    def issue(self, *, plan_hash: str, user_id: str, step_up: bool = False) -> str:
        payload = {"ph": plan_hash, "uid": user_id,
                   "exp": int((self.clock() + timedelta(seconds=self.ttl_s)).timestamp()),
                   "n": secrets.token_hex(8), "su": bool(step_up)}
        body = _b64(json.dumps(payload, sort_keys=True).encode())
        return f"{body}.{hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()}"

    def parse(self, token: str) -> dict:
        try:
            body, sig = token.rsplit(".", 1)
            good = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, good):
                raise ValueError("bad signature")
            return json.loads(_unb64(body))
        except Exception as e:
            raise PolicyDenied("APPROVAL_INVALID",
                               "approval token is malformed or not signed by the approval service") from e


class PolicyEngine:
    def __init__(self, approvals: ApprovalService, limits: Limits, ledger, fx, clock=utcnow):
        self.approvals, self.limits, self.ledger, self.fx, self.clock = approvals, limits, ledger, fx, clock

    def authorize_tool(self, name: str, tier: Tier, allowed: frozenset, cap: Tier) -> None:
        """Layer 1 (allow-list) + layer 2 (tier cap). Agents are capped at PROPOSE; only the human path gets EXECUTE."""
        if name not in allowed:
            raise PolicyDenied("TOOL_NOT_ALLOWED", f"tool '{name}' is not allowed for this caller")
        if tier > cap:
            raise PolicyDenied("TIER_EXCEEDED", f"tool '{name}' needs tier {tier.name}; caller is capped at {cap.name}")

    def to_ref_minor(self, amount_minor: int, ccy: str) -> int:
        return int((Decimal(amount_minor) * self.fx.quote(ccy, "EUR").rate).quantize(Decimal(1)))

    def authorize_payment(self, session, plan, token: str) -> dict:
        """Layer 3: every check that must pass before money moves. Order = cheapest/most specific first."""
        now = self.clock()
        if plan is None:
            raise PolicyDenied("NO_PLAN", "there is no payment plan to execute")
        if not session.kyc_verified:
            raise PolicyDenied("KYC_REQUIRED", "customer identity verification is not complete")
        p = self.approvals.parse(token)
        if p["uid"] != session.user_id or plan.user_id != session.user_id:
            raise PolicyDenied("APPROVAL_WRONG_USER", "approval was not issued for this user")
        if self.ledger.nonce_used(p["n"]):
            raise PolicyDenied("APPROVAL_ALREADY_USED", "this approval was already used (replay blocked)")
        if self.ledger.payment_for_plan(plan.hash()):
            raise PolicyDenied("ALREADY_EXECUTED", "this plan was already paid; no second debit")
        if p["exp"] < int(now.timestamp()):
            raise PolicyDenied("APPROVAL_EXPIRED", "approval has expired; ask the user to approve again")
        if plan.hash() != p["ph"]:
            raise PolicyDenied("APPROVAL_PLAN_MISMATCH", "plan differs from the one that was approved")
        if plan.verification_status == "BLOCKED":
            raise PolicyDenied("VERIFICATION_BLOCKED", "beneficiary verification failed")
        if plan.verification_status == "REVIEW" and not p.get("su"):
            raise PolicyDenied("STEP_UP_REQUIRED", "beneficiary needs manual review: step-up approval required")
        if (now - datetime.fromisoformat(plan.quoted_at)).total_seconds() > plan.quote_ttl_s:
            raise PolicyDenied("STALE_QUOTE", "FX quote expired; re-quote and re-approve")
        if self.limits.require_live_fx and plan.quote_source not in LIVE_SOURCES:
            raise PolicyDenied("INDICATIVE_FX_NOT_ALLOWED", "only live FX quotes may be executed")
        if plan.beneficiary.get("country") in self.limits.high_risk_countries:
            raise PolicyDenied("SCREENING_HIT", "destination country requires compliance review")
        acct = self.ledger.account(plan.account_id)
        if acct["owner"] != session.user_id or acct["currency"] != plan.src_ccy:
            raise PolicyDenied("ACCOUNT_NOT_OWNED", "source account does not belong to this user/currency")
        ref = self.to_ref_minor(plan.dst_amount_minor, plan.dst_ccy)
        if ref > self.limits.per_tx_ref_minor:
            raise PolicyDenied("PER_TX_LIMIT", "payment exceeds the per-transaction limit")
        count, total = self.ledger.daily_totals(session.user_id, now.date().isoformat())
        if count >= self.limits.max_payments_per_day:
            raise PolicyDenied("VELOCITY_LIMIT", "too many payments today")
        if total + ref > self.limits.daily_ref_minor:
            raise PolicyDenied("DAILY_LIMIT", "daily payment limit would be exceeded")
        if self.ledger.balance(plan.account_id) < plan.src_total_minor:
            raise PolicyDenied("INSUFFICIENT_FUNDS", "balance is too low for this payment")
        return {**p, "ref_minor": ref}
