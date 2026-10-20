"""Route comparison: total landed cost, arrival time and deadline feasibility. Pure deterministic code.

For each route r and a recipient amount A (in the destination currency) with mid-market rate m (1 src = m dst):
    effective rate      e_r   = m * (1 - fx_margin_r)
    conversion cost     C_r   = A / e_r                                  (in source currency)
    fee                 F_r   = C_r * pct_fee_r + fixed_fee_r            (fixed fee converted from EUR)
    total               T_r   = C_r + F_r
    hidden + explicit cost vs mid-market = T_r - A / m
Feasible  <=>  now + worst-case ETA + safety buffer <= end of the due date (UTC).
Recommendation = cheapest feasible route; if none is feasible, the fastest route plus a deadline warning."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from .fx import DATA_DIR, FXQuote
from .invoice import Invoice
from .money import fmt, from_minor, to_minor


@dataclass
class RouteOption:
    route_id: str
    name: str
    src_total_minor: int
    conversion_src_minor: int
    fee_src_minor: int
    fx_margin_pct: str
    effective_rate: str
    eta_hours_min: int
    eta_hours_max: int
    arrives_by: datetime
    deadline_ok: bool
    cost_vs_mid_minor: int
    cost_pct: str


@dataclass
class RouteComparison:
    src_ccy: str
    dst_ccy: str
    options: list[RouteOption]
    excluded: list[dict]
    recommended_id: str | None
    baseline_id: str
    savings_vs_baseline_minor: int
    savings_pct: str
    deadline_risk: bool
    rationale: str

    def option(self, route_id: str | None) -> RouteOption | None:
        return next((o for o in self.options if o.route_id == route_id), None)

    def summary(self) -> dict:
        return {"recommended": self.recommended_id, "deadline_risk": self.deadline_risk,
                "savings_vs_baseline_minor": self.savings_vs_baseline_minor, "savings_pct": self.savings_pct,
                "src_ccy": self.src_ccy, "dst_ccy": self.dst_ccy, "rationale": self.rationale,
                "options": [{"route": o.route_id, "name": o.name, "total_minor": o.src_total_minor,
                             "fee_minor": o.fee_src_minor, "fx_margin_pct": o.fx_margin_pct,
                             "eta_hours_max": o.eta_hours_max, "deadline_ok": o.deadline_ok,
                             "cost_pct": o.cost_pct} for o in self.options],
                "excluded": self.excluded}


def compare_routes(inv: Invoice, quote: FXQuote, fx, now: datetime, fees_path=None, buffer_hours: int = 24,
                   baseline_id: str = "bank_wire") -> RouteComparison:
    routes = json.loads(Path(fees_path or DATA_DIR / "fees.json").read_text())["routes"]
    src, dst = quote.base, quote.quote
    need = from_minor(inv.amount_minor, dst)                 # recipient must receive exactly this
    mid_src = need / quote.rate
    amount_eur = need / fx.quote("EUR", dst).rate
    eur_to_src = fx.quote("EUR", src).rate
    due_end = datetime.combine(inv.due_date, time(23, 59, 59), tzinfo=timezone.utc)

    options, excluded = [], []
    for r in routes:
        if amount_eur > Decimal(str(r["max_amount_eur"])):
            excluded.append({"route_id": r["id"], "name": r["name"],
                             "reason": f"amount exceeds the route limit of {r['max_amount_eur']} EUR"})
            continue
        margin = Decimal(str(r["fx_margin_pct"])) / 100 if src != dst else Decimal(0)
        eff = quote.rate * (1 - margin)
        conv = need / eff
        fee = conv * Decimal(str(r["pct_fee"])) / 100 + Decimal(str(r["fixed_fee_eur"])) * eur_to_src
        conv_m, fee_m = to_minor(conv, src), to_minor(fee, src)
        total = conv_m + fee_m
        arrives = now + timedelta(hours=r["eta_hours"][1])
        mid_m = to_minor(mid_src, src)
        extra = total - mid_m
        options.append(RouteOption(
            r["id"], r["name"], total, conv_m, fee_m, str((margin * 100).normalize()),
            str(eff.quantize(Decimal("0.000001"))), r["eta_hours"][0], r["eta_hours"][1], arrives,
            arrives + timedelta(hours=buffer_hours) <= due_end, extra,
            str((Decimal(extra) / Decimal(max(1, mid_m)) * 100).quantize(Decimal("0.01")))))
    options.sort(key=lambda o: o.src_total_minor)

    feasible = [o for o in options if o.deadline_ok]
    risk = not feasible
    rec = (feasible[0] if feasible else min(options, key=lambda o: o.eta_hours_max)) if options else None
    base = next((o for o in options if o.route_id == baseline_id), None)
    sav = max(0, base.src_total_minor - rec.src_total_minor) if base and rec else 0
    sav_pct = str((Decimal(sav) / Decimal(base.src_total_minor) * 100).quantize(Decimal("0.01"))) if base and sav else "0.00"
    if rec is None:
        why = "No route supports this amount."
    elif risk:
        why = (f"No route is guaranteed to arrive {buffer_hours}h before the deadline; {rec.name} is the fastest "
               "option - pay immediately or ask the institution for an extension.")
    else:
        why = (f"{rec.name} is the cheapest route that still arrives at least {buffer_hours}h before the deadline "
               f"(costs {fmt(rec.cost_vs_mid_minor, src)} / {rec.cost_pct}% above the mid-market rate)")
        why += f"; saves {fmt(sav, src)} ({sav_pct}%) versus a standard bank wire." if sav else "."
    return RouteComparison(src, dst, options, excluded, rec.route_id if rec else None, baseline_id, sav, sav_pct,
                           risk, why)
