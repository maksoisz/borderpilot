# BorderPilot: Security Self-Assessment Report

FinTechathon 2026, International Track, Topic C · Team `Financial Mogers` · Version 0.1 · October 2026

This report covers the two items the competition asks for: **how the permission tiers are implemented** and **the list of known risks**. Every control below is linked to the code that enforces it and the automated test that attacks it.

---

## 1. Scope, assets and trust boundaries

**In scope:** the BorderPilot agent, its tools, the policy engine, the sandbox ledger, the local web server and the web UI, in the offline (deterministic planner) and Claude tool-use modes.

**Assets we protect**

| Asset | Why it matters |
|---|---|
| The student's money | Cross-border payments are hard or impossible to recall. |
| Payment details (beneficiary account, amount) | Changing either redirects or inflates a payment. |
| The approval decision | It is the only thing that authorises money movement. |
| The audit trail | It is how a bank, regulator or student reconstructs what happened. |
| Personal data on invoices | Names, student IDs and account numbers. |

**Trust boundaries**

| Untrusted | Trusted |
|---|---|
| Invoice text (any sender can write anything) | Policy engine (`policy.py`) |
| Language-model output, including tool calls | Ledger and its constraints (`ledger.py`) |
| Network data (FX API) | Approval service (HMAC key held server-side) |
| Browser input to the server | Deterministic domain logic (extraction, verification, routing) |

## 2. Permission tiers: implementation

### 2.1 Tiers

| Tier | Meaning | Tools |
|---|---|---|
| `READ` (0) | Analyse; no side effects beyond audit | `read_invoice`, `verify_payee`, `get_fx_quote`, `compare_routes`, `forecast_budget` |
| `PROPOSE` (1) | Create a payment slip for human review; no money moves | `propose_payment` |
| `EXECUTE` (2) | Move money | `execute_payment` |

### 2.2 Who can use which tier

| Caller | Allow-list | Tier cap | Where enforced |
|---|---|---|---|
| Agent (deterministic planner or Claude) | `AGENT_TOOLS`: the five READ tools + `propose_payment` | `PROPOSE` (`Session.max_tier`) | `BorderPilot.call_tool` → `PolicyEngine.authorize_tool` |
| Student via the UI approval endpoint | `AGENT_TOOLS` + `HUMAN_ONLY_TOOLS` (`execute_payment`) | `EXECUTE` | `BorderPilot.approve` → `call_tool(actor="user")` |

Layering: **(1)** the model is never shown the `execute_payment` schema; **(2)** if it calls the tool anyway, the allow-list rejects it (`TOOL_NOT_ALLOWED`); **(3)** if the allow-list were misconfigured, the tier cap rejects it (`TIER_EXCEEDED`); **(4)** if both were bypassed, `execute_payment` still demands a valid human-signed approval token for the exact plan, which the agent has no way to create.

### 2.3 The approval token

- Issued only by `ApprovalService.issue`, called only from `BorderPilot.approve`, which is called only by the `/api/approve` endpoint after the student reviewed the slip and sent back its fingerprint.
- Format: `base64url(payload).HMAC-SHA256(secret, payload)`; 32-byte random secret generated per process.
- Payload binds: plan fingerprint (SHA-256 of every material field), user ID, expiry (10 minutes), random nonce (single use), step-up flag.
- `approve()` first compares the fingerprint the student saw with the current plan; any difference is refused before a token exists.

### 2.4 Checks before money moves (`PolicyEngine.authorize_payment`)

1 plan exists · 2 KYC complete · 3 HMAC signature valid · 4 token user = session user = plan user · 5 nonce not used before · 6 plan not already paid · 7 token not expired · 8 token fingerprint = current plan fingerprint · 9 verification ≠ BLOCKED · 10 step-up present if REVIEW · 11 FX quote within its 10-minute TTL · 12 live FX if configured · 13 destination not on the screening list · 14 source account owned by the user and in the plan currency · 15 per-transaction limit (15,000 EUR equivalent) · 16 payments-per-day limit (3) · 17 daily amount limit (25,000 EUR equivalent) · 18 sufficient balance.

Then `Ledger.record_payment` performs the debit, payment row (`UNIQUE(plan_hash)`), nonce (primary key) and audit entry in **one transaction**, re-checking idempotency and balance inside it.

### 2.5 Tool-level preconditions

`propose_payment` refuses unless the invoice is complete, `verify_payee` has run, the result is not BLOCKED, the route is one that was compared, the FX quote is fresh, and the funding account covers the total. The model therefore cannot skip verification or propose an unaffordable payment.

## 3. Threat model and controls

Mapped to the OWASP Top 10 for LLM Applications (2025 edition) where relevant. "Drill" names refer to `borderpilot/drills.py`; every drill also runs in `tests/test_agent_and_security.py`.

| # | Threat | Control | Evidence (drill / test) | Result |
|---|---|---|---|---|
| T1 | Prompt injection in an invoice (LLM01) | Injection signals block the payee (70 pts); document passed to the model fenced and sanitised; tools take document IDs; payment details come from deterministic extraction | `injection_document`; eval: 3 explicit injections blocked, 3 paraphrased injections harmless | Stopped |
| T2 | Hijacked model tries to pay (LLM06 Excessive Agency) | Allow-list, tier cap, human-only approval | `agent_self_execute`, `tier_escalation`, `unknown_tool` | Stopped |
| T3 | Model skips verification | Tool preconditions | `propose_without_verification` | Stopped |
| T4 | Model leaks or rewrites account numbers (LLM02) | Masked tool output; no free-text payment fields | `model_never_sees_full_account` | Stopped |
| T5 | Model invents amounts (LLM09 Misinformation, LLM05 Improper Output Handling) | Number-grounding guard; template fallback; UI escapes all text | `hallucinated_numbers`, `test_llm_ungrounded_summary_is_withheld` | Stopped |
| T6 | Runaway agent loop (LLM10 Unbounded Consumption) | 12-step limit, deterministic fallback | `test_llm_step_limit` | Stopped |
| T7 | "Bank details changed" fraud | Official-account registry, IBAN checksum | eval `*-swap-new-details`, `*-forged-digit` | Blocked |
| T8 | Look-alike sender, impersonated payee | Domain and name similarity rules | eval `*-lookalike-domain`, `*-impersonated-payee` | Review / Blocked |
| T9 | Forged approval | HMAC signature | `forged_token` | Stopped |
| T10 | Replay or double click | Single-use nonce; idempotency on plan fingerprint | `replay`, `double_click` | Stopped, debited once |
| T11 | Plan changed after approval | Fingerprint binding | `plan_tamper`, `amount_tamper` | Stopped |
| T12 | Stale approval or FX quote | 10-minute expiry and TTL | `expired_approval`, `stale_quote` | Stopped |
| T13 | Approval for another user | User binding | `wrong_user` | Stopped |
| T14 | Compromised orchestrator pushes a BLOCKED payee with step-up | Execution re-checks verification status | `blocked_beneficiary_bypass` | Stopped |
| T15 | Suspicious payee paid without extra care | Step-up required for REVIEW | `review_needs_step_up` | Stopped |
| T16 | Large or repeated payments | Per-transaction, daily and velocity limits | `per_tx_limit`, `velocity_limit` | Stopped |
| T17 | Payment before identity checks | KYC gate | `kyc_required` | Stopped |
| T18 | Overdraft, unaffordable plan | Affordability at proposal; balance at execution; DB constraint | `unaffordable_plan`, `insufficient_funds` | Stopped |
| T19 | Crash mid-payment | Single atomic transaction | `atomic_rollback` | Rolled back |
| T20 | Audit log edited or entry deleted | SHA-256 hash chain | `audit_tamper`, `test_audit_chain_detects_edits_and_deletions` | Detected |
| T21 | Malicious browser input (XSS, oversized requests) | HTML escaping of all dynamic text, CSP, 64 KB limit, JSON only, localhost bind | `test_page_and_security_headers`, `test_rejects_oversized_and_empty` | Mitigated |

## 4. Known-risk list

Severity reflects impact if the risk materialised in a production deployment; likelihood reflects the current design.

| ID | Risk | Severity | Likelihood | Current mitigation | Residual risk and plan |
|---|---|---|---|---|---|
| R1 | **Unregistered payees** (a private landlord) cannot be verified; a careless user who completes step-up could pay a fraudster. Shown in the evaluation: 2/2 genuine unregistered payees correctly went to step-up, which also means a fake "landlord" would too. | High | Medium | REVIEW status, step-up confirmation, warning text | Add payee-name checks (Verification/Confirmation of Payee), a first-payment cap and cooling-off for new payees. |
| R2 | **Keyword-based injection detection** misses paraphrases (3/30 attack scenarios). | Low | Medium | Containment: document IDs, deterministic extraction, masked outputs; no payout occurred | Add a trained classifier as an extra signal; keep containment as the primary control. |
| R3 | **Registry accuracy:** if the official-details registry is wrong or poisoned, verification is wrong. | High | Low | Registry is read-only at runtime; changes only via code review | Signed registry entries with source URL and date; dual control for updates; sourcing from institutions and bank payee-verification services. |
| R4 | **Demo server has no login** and treats a click as the approval. | High (prod) | n/a in sandbox | Binds to localhost; single-user demo | Strong customer authentication (passkey/WebAuthn or banking-app confirmation), device binding, session management. |
| R5 | **HMAC key management:** the key lives in process memory and is regenerated on restart. | Medium | Low | 32-byte random key, never logged or sent to the model | Key in an HSM or cloud KMS, rotation, per-environment keys. |
| R6 | **Illustrative FX and fees:** sample data may differ from real prices; ECB reference rates are not executable rates. | Medium | High (in demo) | UI labels the source; 10-minute quote TTL; `require_live_fx` setting refuses indicative quotes when enabled | Provider-locked executable quotes stored in the plan. |
| R7 | **Audit chain stored with the data:** an attacker with full database write access could recompute the entire chain consistently. | Medium | Low | Edits and deletions of individual entries are detected | Periodically anchor the latest hash outside the database (write-once storage or a timestamping service). |
| R8 | **Screening list empty:** sanctions/AML screening is a hook, not a service. | High (prod) | n/a in sandbox | Check exists in the authorisation order | Integrate a screening provider before any real money movement. |
| R9 | **Text-only invoices:** PDF or image invoices are not parsed; layout tricks could confuse the parser. | Medium | Medium | Missing fields stop the flow (NEEDS_INFO); conflicting fields flagged | Two independent extractors (parser and model) cross-checked, as the optional LLM cross-check already does for text. |
| R10 | **Model wording can mislead** even when numbers are grounded. | Low | Low | Template fallback; slip fields (not prose) are what the student signs | Claim-checking against the plan fields; user testing of explanations. |
| R11 | **Personal data retention:** invoice text is kept in memory for the session. | Medium | Low | Masked accounts in logs, audit and model context; no external calls in offline mode | Retention limits, encryption at rest, data-subject request handling. |
| R12 | **Concurrency:** tested with sequential requests on SQLite. | Low | Low | `UNIQUE(plan_hash)`, nonce primary key and a single transaction guard double execution | Load and race testing on a server database. |
| R13 | **Time-zone edges:** daily limits and deadlines use UTC days. | Low | Low | 24-hour arrival buffer before the due date | Use the institution's local time zone for deadlines. |
| R14 | **External model provider:** availability, cost and data sent to the provider in Claude mode. | Medium | Medium | Offline deterministic fallback; only sanitised, fenced text and masked tool outputs are sent | Data-processing agreement, regional hosting, rate limits and spend caps. |

## 5. Verification

- `python -m borderpilot.drills`: 24 / 24 attacks stopped.
- `python -m unittest discover -s tests -t .`: 35 tests pass, including every drill, the HTTP server and evaluation thresholds.
- `python -m borderpilot.evaluate`: 0 / 30 attacker payouts for both the cautious and the careless user.
- `python -m borderpilot.demo`: produces `evidence/operation_log.jsonl`; the chain was re-verified independently of the application code.

## 6. Conclusion

The strongest property of BorderPilot is not that it detects fraud (it does, in 27 of 30 cases) but that **detection is not what keeps money safe**. A fully compromised model can neither see full account numbers, nor change payment details, nor approve its own plan, and every approval is cryptographically bound to the exact slip a human read. The largest open risk is paying a genuinely new payee (R1), which needs payee-name verification services that exist only in production banking infrastructure.
