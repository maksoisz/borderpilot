"""Multi-currency budget: categorise spend, average burn, runway forecast in the home currency."""
from __future__ import annotations

from decimal import Decimal

CATEGORY_RULES = [("tuition", ("tuition", "university fee")), ("rent", ("rent", "landlord")),
                  ("groceries", ("grocer", "supermarket", "market")),
                  ("transport", ("transport", "metro", "bus ", "train", "ticket")),
                  ("subscriptions", ("subscription", "streaming", "phone plan"))]


def categorize(description: str) -> str:
    d = description.lower()
    for cat, keys in CATEGORY_RULES:
        if any(k in d for k in keys):
            return cat
    return "other"


def to_home(minor: int, ccy: str, home: str, fx) -> int:
    if ccy == home:
        return minor
    return int((Decimal(minor) * fx.quote(ccy, home).rate).quantize(Decimal(1)))


def monthly_burn(transactions: list[dict], home_ccy: str, fx, months: int = 3) -> int:
    """Average monthly recurring spend in home-currency minor units; one-off tuition excluded."""
    total = sum(-to_home(t["amount_minor"], t["currency"], home_ccy, fx) for t in transactions
                if t["amount_minor"] < 0 and categorize(t["description"]) != "tuition")
    return int(total / months)


def spend_by_category(transactions: list[dict], home_ccy: str, fx) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in transactions:
        if t["amount_minor"] < 0:
            c = categorize(t["description"])
            out[c] = out.get(c, 0) + (-to_home(t["amount_minor"], t["currency"], home_ccy, fx))
    return out


def forecast_runway(balances: list[dict], home_ccy: str, fx, monthly_burn_minor: int,
                    monthly_income_minor: int = 0, min_safe_months: int = 3) -> dict:
    total = sum(to_home(b["balance_minor"], b["currency"], home_ccy, fx) for b in balances)
    net = monthly_burn_minor - monthly_income_minor
    if net <= 0:
        return {"home_ccy": home_ccy, "total_home_minor": total, "monthly_net_burn_minor": net,
                "runway_months": None, "status": "SUSTAINABLE"}
    months = (Decimal(total) / Decimal(net)).quantize(Decimal("0.1"))
    status = "CRITICAL" if months < Decimal("1.5") else "WARNING" if months < min_safe_months else "OK"
    return {"home_ccy": home_ccy, "total_home_minor": total, "monthly_net_burn_minor": net,
            "runway_months": str(months), "status": status}
