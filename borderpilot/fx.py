"""FX quotes.

StaticFX     - offline sample mid-market rates (tests, evaluation, offline demo). Clearly labelled as indicative.
FrankfurterFX - ECB reference rates from the public Frankfurter API, cached for 60 s, with automatic fallback to
                StaticFX. Not exercised against the live API in the build environment (no outbound network there).
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from .common import utcnow

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
LIVE_SOURCES = {"frankfurter-ecb"}


class FXError(Exception):
    pass


@dataclass(frozen=True)
class FXQuote:
    base: str
    quote: str
    rate: Decimal            # mid-market: 1 base = rate quote
    quoted_at: datetime
    source: str
    ttl_s: int = 600

    @property
    def quote_id(self) -> str:
        raw = f"{self.base}|{self.quote}|{self.rate}|{self.quoted_at.isoformat()}|{self.source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    def is_fresh(self, now: datetime) -> bool:
        return (now - self.quoted_at).total_seconds() <= self.ttl_s

    @property
    def is_live(self) -> bool:
        return self.source in LIVE_SOURCES


class StaticFX:
    """Illustrative mid-market rates from data/fx_sample.json (NOT real-time)."""

    def __init__(self, path=None, clock=utcnow, age_s: int = 0):
        data = json.loads(Path(path or DATA_DIR / "fx_sample.json").read_text())
        self.per_eur = {k: Decimal(str(v)) for k, v in data["rates_per_EUR"].items()}
        self.clock, self.age_s = clock, age_s

    def quote(self, base: str, quote: str) -> FXQuote:
        now = self.clock() - timedelta(seconds=self.age_s)
        if base == quote:
            return FXQuote(base, quote, Decimal(1), now, "identity")
        try:
            rate = (self.per_eur[quote] / self.per_eur[base]).quantize(Decimal("0.00000001"))
        except KeyError as e:
            raise FXError(f"no rate for {base}->{quote}") from e
        return FXQuote(base, quote, rate, now, "static-sample")


class FrankfurterFX:
    def __init__(self, fallback: StaticFX, base_url: str | None = None, timeout: float = 5.0, clock=utcnow):
        self.fallback, self.timeout, self.clock = fallback, timeout, clock
        self.base_url = (base_url or os.environ.get("BORDERPILOT_FX_URL") or "https://api.frankfurter.dev/v1").rstrip("/")
        self._cache: dict = {}

    def quote(self, base: str, quote: str) -> FXQuote:
        if base == quote:
            return self.fallback.quote(base, quote)
        hit = self._cache.get((base, quote))
        if hit and (self.clock() - hit.quoted_at).total_seconds() < 60:
            return hit
        q = self._fetch(base, quote)
        self._cache[(base, quote)] = q
        return q

    def _fetch(self, base: str, quote: str) -> FXQuote:
        try:
            url = f"{self.base_url}/latest?base={base}&symbols={quote}"
            with urllib.request.urlopen(url, timeout=self.timeout) as r:  # noqa: S310 (fixed https URL)
                data = json.load(r)
            return FXQuote(base, quote, Decimal(str(data["rates"][quote])), self.clock(), "frankfurter-ecb")
        except Exception:
            return replace(self.fallback.quote(base, quote), source="fallback-static")
