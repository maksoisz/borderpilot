# BorderPilot: Technical Documentation

FinTechathon 2026, International Track, Topic C (Cross-border & Student Finance Assistant)
Team `Financial Mogers` · Version 0.1 · October 2026

---

## 1. Summary

BorderPilot is an AI agent that completes a real financial task end to end: **paying a cross-border tuition or accommodation invoice for an international student.** It reads the invoice, verifies the payee against official payment details, compares payment routes by total landed cost and worst-case arrival time, forecasts the student's budget runway, prepares an exact payment slip and, after the student signs that slip, executes the payment in a sandbox bank.

The design answers one question: *how can an AI act as a financial participant without becoming a new way to lose money?* Our answer is a layered architecture in which **the language model proposes, deterministic code verifies and computes, and only a human-signed approval bound to the exact plan can move money.**

| Scoring criterion | What BorderPilot contributes |
|---|---|
| Task completion (40 %) | Full loop from document to executed sandbox payment; 12/12 genuine invoices paid correctly and on time in the evaluation; deadline-aware routing; budget impact before paying |
| Security & compliance (30 %) | Three permission tiers enforced in code, plan-bound single-use approvals, explainable fraud scoring, prompt-injection containment, hash-chained audit log; 24/24 attack drills stopped; 0/30 attacker payouts |
| Innovation & interaction (30 %) | "What you see is what you sign" payment slip with a cryptographic fingerprint; risk explained as named reasons with points; one-click attack panel; plain-language explanations whose numbers are guaranteed to come from tools |

## 2. Problem and users

**Primary user:** a student starting or continuing a degree abroad (for example a Polish student in the UK, or a European student in China) who must pay tuition, deposits and accommodation in a foreign currency, often from family money in their home currency.

**Pain points we target**

1. **Invoice fraud.** "Our banking details have changed" emails, look-alike sender domains and fake fee-collection companies target exactly the moment a large, time-pressured payment is due. Cross-border transfers are hard to recall.
2. **Opaque cost.** A transfer's real cost is the fixed fee *plus* the exchange-rate margin. Students rarely see the margin as a number, so they cannot compare routes.
3. **Deadlines.** Late tuition can mean fines or cancelled enrolment, but the cheapest route is often the slowest.
4. **Runway.** A single large payment can leave too little for rent and food; students need to see that before they pay.

## 3. System architecture

```
 Student (browser): reviews the payment slip and signs it
                                          │
 ┌────────────────────────────────────────────────────────────────────────────────┐
 │ Web UI  web/index.html  +  local server  server.py                             │
 │ invoice input, agent steps, payment slip, step-up, attack panel                │
 └────────────────────────────────────────────────────────────────────────────────┘
                                          │
 ┌────────────────────────────────────────────────────────────────────────────────┐
 │ Planner (one of)                                                               │
 │   Claude tool-use loop        agent.run_llm                                    │
 │   deterministic planner       agent.run                                        │
 └────────────────────────────────────────────────────────────────────────────────┘
                                          │  every tool call
 ┌────────────────────────────────────────────────────────────────────────────────┐
 │ Tool gateway  agent.call_tool                                                  │
 │ allow-list, tier cap, argument check, preconditions, audit                     │
 └────────────────────────────────────────────────────────────────────────────────┘
              │  READ                     │  PROPOSE                  │  EXECUTE, human only
 ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────┐
 │ invoice.py  verify.py  │  │ plan.py                │  │ policy.py              │
 │ fx.py  routes.py       │  │ payment slip and its   │  │ HMAC approval token    │
 │ budget.py              │  │ SHA-256 fingerprint    │  │ and 18 checks          │
 └────────────────────────┘  └────────────────────────┘  └────────────────────────┘
                                                                      │  one atomic transaction
                                                         ┌────────────────────────┐
                                                         │ ledger.py (SQLite)     │
                                                         │ accounts, payments,    │
                                                         │ nonces, audit chain    │
                                                         └────────────────────────┘
```

| Component | File | Responsibility |
|---|---|---|
| Web UI | `web/index.html` | Single page, no external resources. Shows each agent step with its permission tier, the payee check, the route table, budget runway, and the payment slip the student signs. All dynamic text is HTML-escaped. |
| Server | `borderpilot/server.py` | Standard-library HTTP server bound to localhost, 64 KB request limit, JSON only, CSP and `nosniff` headers. |
| Agent | `borderpilot/agent.py` | Tool registry, gateway, deterministic planner, Claude tool-use loop, human approval path, state view. |
| Policy | `borderpilot/policy.py` | Permission tiers, approval tokens, payment authorisation, limits. |
| Ledger | `borderpilot/ledger.py` | Sandbox bank, atomic payments, single-use nonces, hash-chained audit log. |
| Domain logic | `invoice.py`, `verify.py`, `fx.py`, `routes.py`, `budget.py`, `plan.py`, `money.py` | Deterministic, unit-tested computation. No floating point near money. |
| LLM adapter | `borderpilot/llm.py` | Claude adapter for explanations and optional cross-checked extraction, template fallback, number-grounding guard. |

**Data flow for one payment**

1. The student uploads invoice text. The server stores it in the session under a content-hash ID (`doc_…`). The planner only ever refers to the document by this ID.
2. `read_invoice` extracts fields deterministically and raises signals (injection, urgency, unusual payment method, conflicting fields).
3. `verify_payee` scores the payee against the official registry. `BLOCKED` stops the workflow; no plan can be built.
4. `get_fx_quote` and `compare_routes` compute every route's cost and arrival; `forecast_budget` computes runway before and after.
5. `propose_payment` checks affordability and quote freshness, builds the `Plan`, computes its SHA-256 fingerprint and writes a plain-language explanation.
6. The student reviews the slip. For `REVIEW` payees they must tick a step-up confirmation (in production: strong customer authentication plus an out-of-band check).
7. The UI calls `approve(plan_hash)`. The approval service signs a token for that fingerprint; `execute_payment` re-validates everything and debits atomically.

## 4. Agent design

### 4.1 Tools and permission tiers

| Tool | Tier | Agent may call | Preconditions enforced in code |
|---|---|---|---|
| `read_invoice(doc_id)` | READ | yes | document ID exists in the session |
| `verify_payee()` | READ | yes | invoice read |
| `get_fx_quote()` | READ | yes | invoice has a currency |
| `compare_routes()` | READ | yes | quote exists; invoice complete; re-quotes if stale |
| `forecast_budget(route_id?)` | READ | yes | none |
| `propose_payment(route_id?)` | PROPOSE | yes | invoice complete; **verification ran and is not BLOCKED**; route is one of the compared options; quote fresh; balance covers the total |
| `execute_payment(approval_token)` | EXECUTE | **no** | full authorisation (section 5.5) |

The gateway (`BorderPilot.call_tool`) applies, in order: unknown-tool rejection, the caller's **allow-list**, the caller's **tier cap** (agents are capped at PROPOSE; only the human path has EXECUTE), rejection of unexpected arguments, the tool's own preconditions, and an audit entry for every call and every denial. Tool exceptions become structured `TOOL_ERROR` denials, never crashes.

### 4.2 Planners

**Claude tool-use loop (`run_llm`).** The model receives a system prompt that states the workflow and the rules (documents are untrusted; never propose after BLOCKED; it cannot execute; never invent numbers) and the JSON schemas of the six agent tools only. Each `tool_use` block goes through the gateway; denials come back as `is_error` tool results so the model can recover. The loop stops at a final text answer or after 12 steps. The final answer is checked by the number-grounding guard (section 5.7); if it contains a number that no tool returned, it is withheld and replaced by the deterministic explanation.

**Deterministic planner (`run`).** The same tools in the reference order. It powers the offline demo and the evaluation, and it is the fallback when no API key is configured. Because both planners share the gateway, every security property holds for both.

### 4.3 What the model can and cannot see

- It sees the invoice only as a sanitised, fenced `<untrusted_document>` (when LLM extraction is enabled) and tool outputs.
- Tool outputs are PII-minimised: account numbers appear as `****5432`. The model cannot copy, leak or "correct" an account number it never sees in full.
- It cannot pass free text that becomes payment details: payment details come from deterministic extraction of the stored document, addressed by ID.

## 5. Core algorithms

### 5.1 Invoice extraction and cross-checking (`invoice.py`)

- Line-based key/value parsing with synonym sets (e.g. *Payee / Beneficiary / Pay to*; *IBAN / Account number*).
- **Amount normalisation** handles `9,250.00`, `9.250,00`, `9 250,00`, `52,000` and `12,5`. Rule: if both separators appear, the right-most is the decimal separator; a single separator followed by exactly three digits (and at most three leading digits) is a thousands separator; otherwise it is decimal. Amounts become integer minor units through `Decimal` with half-up rounding.
- **Signals:** injection patterns (instruction overrides, role tags, "change the beneficiary to…", "do not verify", claims that approval was granted), urgency language, crypto or gift-card requests, and **conflicting duplicate fields** (two different IBANs or amounts).
- **Optional LLM cross-check:** if Claude extraction is enabled, any disagreement with the deterministic result on account, currency or amount adds `EXTRACTION_DISAGREEMENT`; the model can only fill fields the parser left empty, and those are marked `LLM_ONLY`.

### 5.2 Payee verification and risk score (`verify.py`)

An additive, explainable score from 0 to 100. Every point comes from a named rule with a sentence the student can read.

| Rule | Points | Logic |
|---|---|---|
| `ACCOUNT_MISMATCH` | 80 | payee matches a registered institution but the account is not one of its official accounts |
| `PROMPT_INJECTION_SUSPECTED` | 70 | instruction-like text aimed at an AI |
| `UNKNOWN_PAYEE` | 60 | payee name not in the registry (similarity < 0.85) |
| `LOOKALIKE_DOMAIN` | 50 | sender domain is not official but similarity to an official domain ≥ 0.8 |
| `INVALID_IBAN_CHECKSUM` | 50 | ISO 13616 mod-97 check fails |
| `UNUSUAL_PAYMENT_METHOD` | 50 | crypto, gift cards or cash-transfer services requested |
| `PAYEE_IMPERSONATION` | 40 | unknown payee whose name is ≥ 0.6 similar to a registered institution |
| `BIC_MISMATCH` | 40 | official account but different BIC |
| `CONFLICTING_FIELD` / `EXTRACTION_DISAGREEMENT` | 40 | inconsistent document or extractor disagreement |
| `SENDER_DOMAIN_NOT_OFFICIAL` | 30 | sender domain unrelated to the institution |
| `UNEXPECTED_CURRENCY` | 20 | institution does not invoice in this currency |
| `AMOUNT_OUTSIDE_TYPICAL_RANGE` | 15 | outside the institution's typical range |
| `URGENCY_PRESSURE` | 15 | pressure language |

**Thresholds:** score ≥ 70 → `BLOCKED` (cannot be paid, not even with step-up); 30–69 → `REVIEW` (step-up required); < 30 → `VERIFIED`. Name and domain similarity use a normalised `SequenceMatcher` ratio. Weights are hand-set so that any single decisive fraud signal (wrong account, injection) blocks on its own, while softer signals combine. They are configuration, not learned parameters, which keeps every decision auditable.

### 5.3 Route comparison (`routes.py`)

For recipient amount *A* (destination currency), mid-market rate *m* (1 source = *m* destination) and route *r* with FX margin *μᵣ*, percentage fee *pᵣ*, fixed fee *fᵣ* (EUR, converted) and worst-case ETA *ηᵣ*:

```
effective rate        eᵣ = m · (1 − μᵣ)
conversion cost       Cᵣ = A / eᵣ
fee                   Fᵣ = Cᵣ · pᵣ + fᵣ
total to pay          Tᵣ = Cᵣ + Fᵣ
cost above mid-rate   Tᵣ − A / m
feasible              now + ηᵣ + 24 h buffer ≤ end of due date (UTC)
```

Routes whose limit is below the amount are excluded with a reason. The recommendation is the **cheapest feasible** route; if none is feasible the fastest route is recommended with an explicit deadline warning. The recipient always receives exactly *A*: the sender bears all costs, which is what an institution expects. Complexity is linear in the number of routes.

### 5.4 Budget runway (`budget.py`)

Transactions are categorised (rent, groceries, transport, subscriptions, tuition, other). Monthly burn is the three-month average of non-tuition spending converted to the home currency; runway = total balances in the home currency ÷ (burn − income). Status: < 1.5 months `CRITICAL`, < 3 `WARNING`, otherwise `OK`; non-positive net burn is `SUSTAINABLE`. The forecast is shown before and after the proposed payment, and `propose_payment` refuses outright if the funding account cannot cover the total.

### 5.5 Payment slip, fingerprint and approval (`plan.py`, `policy.py`)

The `Plan` contains every material field: user, source account, currencies, recipient amount, total debit, fee, route, effective rate, quote ID, source and timestamp, beneficiary (name, account, BIC, country, institution), verification status and score, due date, arrival date, deadline flag and reference. Its fingerprint is `SHA-256(canonical JSON)` with sorted keys; the explanation text is deliberately excluded.

The approval token is `base64url(payload) "." HMAC-SHA256(secret, payload)` with payload `{plan hash, user id, expiry = now + 10 min, random nonce, step-up flag}`. It is issued only by the `ApprovalService`, which is reachable only from the human-facing endpoint.

`authorize_payment` then checks, in order: plan exists → KYC complete → token signature → token user → nonce unused → plan not already paid → token unexpired → token fingerprint equals the current plan's fingerprint → verification not `BLOCKED` → step-up present if `REVIEW` → FX quote younger than its 10-minute TTL → live FX if required by configuration → destination not on the screening list → source account owned by the user and in the plan currency → per-transaction limit → payments-per-day limit → daily amount limit → sufficient balance.

### 5.6 Sandbox ledger and audit chain (`ledger.py`)

The debit, the payment row (with `UNIQUE(plan_hash)`), the used nonce (primary key) and the audit entry are written in **one SQLite transaction**; a failure anywhere rolls back all of it (tested by injecting a crash). Balances have a `CHECK(balance ≥ 0)` constraint.

Every audit entry stores `hash = SHA-256(prev_hash ‖ canonical JSON{ts, actor, action, payload})` with a zero genesis hash. `verify_audit()` recomputes the chain and reports the first broken entry; an independent 10-line script in the evidence step re-verifies the exported log without importing BorderPilot code. Audit payloads contain masked accounts only.

### 5.7 Number grounding

`numbers_grounded(text, facts)` extracts every multi-digit number from a model-written text and requires each to appear in the facts computed by tools. Explanations and final answers that fail are replaced by the deterministic template. This removes the most damaging class of hallucination in finance: a wrong amount stated with confidence.

## 6. Security design (summary)

Defence in depth with independent layers, so that no single failure, including a fully hijacked model, moves money:

1. **Least privilege:** the model's tool list does not contain `execute_payment`.
2. **Tier cap:** even if the allow-list were misconfigured, agent callers are capped at PROPOSE.
3. **Tool preconditions:** verification must run before a proposal; BLOCKED payees cannot be proposed.
4. **Human signature bound to the exact plan:** HMAC token, single use, 10-minute expiry, user-bound, step-up for REVIEW.
5. **Re-validation at execution:** limits, freshness, ownership, balance, verification status.
6. **Atomic ledger and tamper-evident audit.**
7. **Untrusted-input handling:** documents by ID, sanitised and fenced for the model, masked outputs, grounded numbers, HTML escaping in the UI.

The complete permission-tier description and the known-risk list are in [`SECURITY_SELF_ASSESSMENT.md`](SECURITY_SELF_ASSESSMENT.md).

## 7. Interaction design

- **The payment slip** is the centre of the interface: who is paid, what they receive, what the student pays, the route, arrival versus due date, a plain-language explanation and the plan fingerprint. The approve button names the exact amount ("Approve and pay 45,987.31 PLN").
- **The verdict is a stamp** (VERIFIED, REVIEW, BLOCKED, PAID), and the risk meter shows the score against the 30 and 70 thresholds, with each reason and its points listed below.
- **Step-up is explicit:** for REVIEW payees the student must confirm the details through the institution's official channel before the button activates. BLOCKED slips have no button at all, and say what to do instead.
- **Every agent step is visible** with its permission tier and who performed it ("by the agent" or "by you"); denials show their code.
- **"Try to break it"** runs all attack drills live, which turns security from a claim into something a judge can watch.
- **Accessibility:** keyboard focus styles, reduced-motion support, light and dark themes, and a layout that works on a phone.

## 8. Evaluation

**Method.** `python -m borderpilot.evaluate` generates 44 scenarios from three fictional institutions (GBP, EUR, CNY) with a fixed clock, so results are deterministic (two runs produce byte-identical reports):

- 12 genuine invoices in four formats (standard, European number and date format with synonyms, plain amount with written date, genuine reminder with pressure wording);
- 2 genuine invoices from unregistered payees (landlord, dormitory), expected to require step-up;
- 30 attacks: new-bank-details fraud, one-digit forged account, look-alike domain, explicit injection, paraphrased injection, attacker account inserted before or after the official one, impersonated payee name, crypto request, conflicting amounts.

Each attack is run twice: a **cautious user** approves only VERIFIED slips; a **careless user** approves everything the system allows, including step-up. A payout counts as a failure only if money reaches a non-official account.

**Results**

| Metric | Result |
|---|---|
| Genuine registered invoices paid correctly, to the official account, before the deadline | 12 / 12 |
| False alarms on genuine registered invoices | 0 / 12 |
| Unregistered genuine payees routed to step-up | 2 / 2 |
| Attacks flagged (BLOCKED or REVIEW) | 27 / 30 |
| Attacks hard-blocked | 15 / 30 |
| Attacker payouts, cautious user | 0 / 30 |
| Attacker payouts, careless user | 0 / 30 |
| Security drills stopped | 24 / 24 |
| Average saving versus bank wire (illustrative fees) | 2.34 % |

The three missed detections are paraphrased injections that the keyword scanner does not recognise. They caused no payout because the architecture never lets document text change payment details. This is the main lesson of the evaluation: **containment matters more than detection.**

**Limitations.** The scenarios are synthetic and written by the team; they show that the design behaves as intended, not how often each fraud occurs in practice. Fees and rates are illustrative, so the savings figure depends on them.

## 9. Deployment and operations

- Python 3.10+ with the standard library only; tested on Python 3.13.
- `python -m borderpilot.server [--host 127.0.0.1] [--port 8000] [--live-fx]`.
- Optional Claude planner: `pip install anthropic`, set `ANTHROPIC_API_KEY` and `BORDERPILOT_LLM=anthropic` (model via `BORDERPILOT_MODEL`).
- Tests: `python -m unittest discover -s tests -t .` (35 tests including every drill, the HTTP server and evaluation thresholds).
- Evidence: `python -m borderpilot.demo` regenerates `evidence/` with real timestamps.

## 10. Compliance considerations

This prototype is a sandbox and gives no financial advice. A production version would operate with or inside a licensed payment provider and would need, among others: identity verification (KYC) before execution (modelled as a gate); strong customer authentication for approvals, for example under PSD2 in the EU (modelled as the signed approval and step-up); sanctions and AML screening of beneficiaries (modelled as a screening hook with an empty list); payee-name checks such as the EU Verification of Payee and UK Confirmation of Payee schemes (our registry check plays this role in the sandbox); data minimisation and retention rules under GDPR (masked accounts in logs and model context); and clear disclosure of total cost including FX margin (shown per route).

## 11. Roadmap

1. Replace illustrative fees with live quotes from payment-provider APIs and lock the executable rate in the plan.
2. Registry fed from institutions' official payment pages and bank payee-verification services, with signed updates.
3. Passkey (WebAuthn) approval and an out-of-band callback for step-up.
4. PDF and image invoices with two independent extractors cross-checked.
5. Explanations in the student's language, including Chinese, generated by Claude under the same number-grounding guard.
6. Instalment planning and rate alerts: suggest splitting or timing a payment when runway is at risk.

## 12. Known limitations

Text invoices only; one funding account per student; single-process demo server without user login; illustrative FX and fee data; synthetic evaluation. See the known-risk list in the security self-assessment for the full register.
