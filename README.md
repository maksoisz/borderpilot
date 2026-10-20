# BorderPilot

**An AI agent that pays study-abroad bills safely: it reads the invoice, checks who you are paying, finds the cheapest route that arrives before the deadline, and moves money only after you sign the exact plan.**

FinTechathon 2026 (Shenzhen International FinTech Competition), International Track, Topic C: Cross-border & Student Finance Assistant. Theme: *AI as a Financial Participant*.

Team: `Financial Mogers` · Members: `Maksymilian Olszewski`, `Szymon Maurer` · Repository: `https://github.com/maksoisz/borderpilot`

---

## The problem

An international student paying tuition abroad faces three risks at once:

1. **Fraud.** "Our bank details have changed" emails and look-alike invoices target exactly this payment, and the money cannot be recalled once sent.
2. **Hidden cost.** Bank wires add fixed fees plus an exchange-rate margin that is rarely shown as a number.
3. **Deadlines and runway.** Paying late can cancel enrolment; paying too much at once can leave a student without money for rent.

An AI agent that can *act* on money must be useful and impossible to talk into a bad payment. BorderPilot is built around that rule: **the model proposes, deterministic code and the human dispose.**

## What it does

| Step | Tool | Permission tier |
|---|---|---|
| Read the invoice (amount, currency, due date, payee, account) and scan it for fraud and prompt-injection signals | `read_invoice` | READ |
| Check the payee and account against a registry of official institution payment details (IBAN checksum, look-alike domains, impersonated names, conflicting fields) | `verify_payee` | READ |
| Get the exchange rate | `get_fx_quote` | READ |
| Compare routes by **total landed cost** and **worst-case arrival** against the due date | `compare_routes` | READ |
| Forecast how many months the student's money lasts before and after paying | `forecast_budget` | READ |
| Prepare the exact payment slip and send it for approval (no money moves) | `propose_payment` | PROPOSE |
| Execute the approved slip in the sandbox bank | `execute_payment` | EXECUTE, **human only** |

The approval is an HMAC-signed, single-use token bound to the SHA-256 fingerprint of the slip, the user, and a 10-minute expiry. Change one digit of the account or amount after approval and the token no longer matches.

## Results (reproducible)

`python -m borderpilot.evaluate` on 44 synthetic scenarios plus 24 attack drills:

| Metric | Result |
|---|---|
| Genuine invoices paid correctly and on time | **12 / 12** |
| False alarms on genuine registered invoices | **0 / 12** |
| Attacks flagged (blocked or sent to step-up) | **27 / 30** |
| Money reaching an attacker, even with a careless user who approves everything allowed | **0 / 30** |
| Attack drills stopped (hijacked AI, forged/replayed approvals, tampered plan or log, limits...) | **24 / 24** |
| Average saving vs. a standard bank wire | 2.34 % (illustrative fee schedule) |

The three detection misses are paraphrased prompt injections. They are harmless by design: the model never handles the full account number and tools take document IDs, so the injected account is never used. Full tables: [`evidence/EVAL_REPORT.md`](evidence/EVAL_REPORT.md).

## Quick start

Requirements: Python 3.10 or newer (tested on 3.13). **No third-party packages are needed.**

```bash
git clone https://github.com/maksoisz/borderpilot && cd borderpilot

python -m borderpilot.server          # open http://127.0.0.1:8000
python -m unittest discover -s tests -t .   # 35 tests
python -m borderpilot.evaluate        # metrics -> evidence/EVAL_REPORT.md
python -m borderpilot.drills          # attack drills -> PASS/FAIL table
python -m borderpilot.demo            # sandbox run -> evidence/ (execution evidence)
```

In the web app: pick a sample invoice, press **Run the agent**, read the payment slip, then **Approve and pay**. Try the fraud samples and the **Run all attacks** button.

### Optional: let Claude plan the steps

The agent loop works with any planner. Offline it uses a deterministic planner; with an API key the same tool gateway is driven by Claude via tool use:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...            # your key
export BORDERPILOT_LLM=anthropic
export BORDERPILOT_MODEL=claude-sonnet-5-5   # optional
python -m borderpilot.server
```

The model receives only the agent tools (never `execute_payment`), sees masked account numbers, and any summary containing a number no tool produced is withheld. Live-API mode was tested with a scripted fake client in this repository; run it with your key before relying on it.

### Optional: live exchange rates

`python -m borderpilot.server --live-fx` uses ECB reference rates from the public Frankfurter API and falls back to the sample table if the network is unavailable. The UI always shows which source is in use.

## Repository layout

```
borderpilot/
  agent.py      tool registry, permission tiers, scripted planner, Claude tool-use loop, human approval path
  policy.py     tier caps, approval tokens (HMAC), payment authorisation checks and limits
  ledger.py     SQLite sandbox bank: atomic payments, single-use nonces, SHA-256 hash-chained audit log
  invoice.py    deterministic extraction, injection/urgency/crypto signals, sanitising for the model
  verify.py     payee verification and explainable risk score
  routes.py     landed-cost and deadline-aware route comparison
  budget.py     multi-currency spending, burn and runway forecast
  plan.py       the payment slip and its fingerprint
  llm.py        Claude adapter, template fallback, number-grounding guard
  drills.py     24 scripted attacks
  evaluate.py   scenario suite and metrics
  demo.py       sandbox run that writes the execution evidence
  server.py     local web server (standard library)
web/index.html  single-page UI
data/           fictional institutions, sample invoices, illustrative FX rates and fees, student profile
evidence/       execution evidence: operation log, transcript, payments, evaluation report
docs/           technical documentation, security self-assessment, demo video script
tests/          unit, agent, security, server and evaluation tests
```

## Submission map

| Required item | Where |
|---|---|
| 01 Technical documentation | [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md) |
| 02 Presentation deck | submitted separately (PDF) |
| 03 Demo video (≤ 5 min) | submitted separately; script in [`docs/DEMO_VIDEO_SCRIPT.md`](docs/DEMO_VIDEO_SCRIPT.md) |
| 04 Source code, README, deployment, tests | this repository, `tests/` |
| 05 Security self-assessment | [`docs/SECURITY_SELF_ASSESSMENT.md`](docs/SECURITY_SELF_ASSESSMENT.md) |
| 06 Execution evidence | [`evidence/`](evidence/): `operation_log.jsonl`, `DEMO_TRANSCRIPT.md`, `payments.json`, `sandbox.db` + demo video |

## Honest limits

- Sandbox only. BorderPilot is not a licensed payment institution and moves no real money.
- Institutions, students and accounts in `data/` are fictional. FX rates and fees are **illustrative**, not any provider's prices; savings figures depend on them.
- The scenario suite is written by the team and synthetic. It measures the design, not real-world fraud prevalence.
- First-time payees (a private landlord) cannot be verified against a registry; they always require step-up confirmation.

## Licence and third-party components

Copyright © 2026 Financial Mogers (Maksymilian Olszewski, Szymon Maurer). All rights reserved; submitted to FinTechathon 2026 under the competition rules.
Runtime uses only the Python standard library. Optional: the `anthropic` Python SDK (MIT licence) and the Frankfurter API (ECB reference data). No third-party code is vendored.
