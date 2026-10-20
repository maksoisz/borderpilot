"""Shared helpers: time, hashing, canonical JSON, account masking, a controllable clock."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FixedClock:
    """Deterministic clock for tests, evaluation and security drills."""

    def __init__(self, start: datetime):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def mask_account(acc: str | None) -> str:
    a = re.sub(r"\s+", "", acc or "")
    return "****" + a[-4:] if a else ""
