"""The payment plan: the exact object a human approves.

Its SHA-256 hash covers every material field (who, how much, which account, which route, which rate, which quote),
so an approval token issued for one plan can never execute a different one ("what you see is what you sign")."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .common import canonical_json, mask_account, sha256_hex


@dataclass
class Plan:
    user_id: str
    account_id: int
    src_ccy: str
    dst_ccy: str
    dst_amount_minor: int
    src_total_minor: int
    fee_minor: int
    route_id: str
    route_name: str
    effective_rate: str
    quote_id: str
    quote_source: str
    quoted_at: str
    quote_ttl_s: int
    beneficiary: dict          # name, account, bic, country, institution_id
    verification_status: str
    risk_score: int
    due_date: str
    arrives_by: str
    deadline_ok: bool
    reference: str | None
    explanation: str = ""      # human-readable text; deliberately NOT part of the hash

    def hash(self) -> str:
        d = asdict(self)
        d.pop("explanation")
        return sha256_hex(canonical_json(d))

    def public(self) -> dict:
        d = asdict(self)
        d["beneficiary"] = {**d["beneficiary"], "account": mask_account(d["beneficiary"].get("account", ""))}
        d["plan_hash"] = self.hash()
        return d
