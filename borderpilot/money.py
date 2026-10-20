"""Exact money arithmetic: integer minor units + Decimal. No floats anywhere near money."""
from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

ZERO_DECIMAL = {"JPY", "KRW", "VND"}


def exponent(ccy: str) -> int:
    return 0 if ccy in ZERO_DECIMAL else 2


def to_minor(amount, ccy: str) -> int:
    e = exponent(ccy)
    d = Decimal(str(amount)).quantize(Decimal(1).scaleb(-e), rounding=ROUND_HALF_UP)
    return int(d.scaleb(e))


def from_minor(minor: int, ccy: str) -> Decimal:
    e = exponent(ccy)
    return Decimal(minor).scaleb(-e).quantize(Decimal(1).scaleb(-e))


def fmt(minor: int, ccy: str) -> str:
    return f"{from_minor(minor, ccy):,.{exponent(ccy)}f} {ccy}"
