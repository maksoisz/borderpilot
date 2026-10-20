"""Sandbox bank: SQLite accounts + payments + single-use approvals + hash-chained audit log.

Every state change that moves money is ONE atomic transaction (debit + payment row + nonce + audit entry):
either all of it happens or none of it does."""
from __future__ import annotations

import json
import sqlite3

from .common import canonical_json, sha256_hex, utcnow

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY, owner TEXT NOT NULL, currency TEXT NOT NULL,
  balance_minor INTEGER NOT NULL CHECK(balance_minor >= 0));
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, owner TEXT NOT NULL, plan_hash TEXT NOT NULL UNIQUE,
  account_id INTEGER NOT NULL, src_ccy TEXT, debited_minor INTEGER, fee_minor INTEGER,
  dst_ccy TEXT, dst_amount_minor INTEGER, fx_rate TEXT, route_id TEXT,
  beneficiary_account TEXT, beneficiary_masked TEXT, ref_amount_minor INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS approvals_used(nonce TEXT PRIMARY KEY, plan_hash TEXT NOT NULL, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


class LedgerError(Exception):
    pass


class InsufficientFunds(LedgerError):
    pass


class Ledger:
    def __init__(self, path: str = ":memory:", clock=utcnow):
        self.clock = clock
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass

    def __del__(self):
        self.close()

    # ---- accounts -------------------------------------------------------
    def open_account(self, owner: str, currency: str, balance_minor: int) -> int:
        with self.db:
            cur = self.db.execute("INSERT INTO accounts(owner,currency,balance_minor) VALUES (?,?,?)",
                                  (owner, currency, balance_minor))
            self._append_audit("system", "account_opened",
                               {"account_id": cur.lastrowid, "owner": owner, "currency": currency,
                                "balance_minor": balance_minor})
        return cur.lastrowid

    def balance(self, account_id: int) -> int:
        row = self.db.execute("SELECT balance_minor FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise LedgerError(f"unknown account {account_id}")
        return row["balance_minor"]

    def account(self, account_id: int) -> dict:
        row = self.db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise LedgerError(f"unknown account {account_id}")
        return dict(row)

    def balances(self, owner: str) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM accounts WHERE owner=? ORDER BY id", (owner,))]

    def payments(self, owner: str | None = None) -> list[dict]:
        if owner:
            rows = self.db.execute("SELECT * FROM payments WHERE owner=? ORDER BY id", (owner,))
        else:
            rows = self.db.execute("SELECT * FROM payments ORDER BY id")
        return [dict(r) for r in rows]

    def nonce_used(self, nonce: str) -> bool:
        return self.db.execute("SELECT 1 FROM approvals_used WHERE nonce=?", (nonce,)).fetchone() is not None

    def payment_for_plan(self, plan_hash: str) -> dict | None:
        row = self.db.execute("SELECT * FROM payments WHERE plan_hash=?", (plan_hash,)).fetchone()
        return dict(row) if row else None

    # ---- audit (hash chain) --------------------------------------------
    def _append_audit(self, actor: str, action: str, payload: dict) -> None:
        last = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else GENESIS
        ts = self.clock().isoformat()
        body = canonical_json({"ts": ts, "actor": actor, "action": action, "payload": payload})
        self.db.execute("INSERT INTO audit(ts,actor,action,payload,prev_hash,hash) VALUES (?,?,?,?,?,?)",
                        (ts, actor, action, canonical_json(payload), prev, sha256_hex(prev + body)))

    def audit(self, actor: str, action: str, payload: dict) -> None:
        with self.db:
            self._append_audit(actor, action, payload)

    def verify_audit(self) -> tuple[bool, int | None]:
        """Recompute the whole chain. Returns (True, None) or (False, first_bad_seq)."""
        prev = GENESIS
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            body = canonical_json({"ts": row["ts"], "actor": row["actor"], "action": row["action"],
                                   "payload": json.loads(row["payload"])})
            if row["prev_hash"] != prev or sha256_hex(prev + body) != row["hash"]:
                return False, row["seq"]
            prev = row["hash"]
        return True, None

    def audit_rows(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY seq")]

    # ---- payments -------------------------------------------------------
    def daily_totals(self, owner: str, day_iso: str) -> tuple[int, int]:
        row = self.db.execute("SELECT COUNT(*) c, COALESCE(SUM(ref_amount_minor),0) s FROM payments "
                              "WHERE owner=? AND ts LIKE ?", (owner, day_iso + "%")).fetchone()
        return row["c"], row["s"]

    def record_payment(self, *, owner, plan_hash, account_id, debit_minor, fee_minor, src_ccy, dst_ccy,
                       dst_amount_minor, fx_rate, route_id, beneficiary_account, beneficiary_masked,
                       ref_amount_minor, nonce, actor="executor") -> dict:
        ts = self.clock().isoformat()
        try:
            with self.db:  # atomic: any exception rolls everything back
                dup = self.db.execute("SELECT * FROM payments WHERE plan_hash=?", (plan_hash,)).fetchone()
                if dup:
                    self._append_audit(actor, "payment_duplicate_ignored", {"plan_hash": plan_hash})
                    return {**dict(dup), "duplicate": True}
                if self.db.execute("SELECT 1 FROM approvals_used WHERE nonce=?", (nonce,)).fetchone():
                    raise LedgerError("approval token already used")
                if self.balance(account_id) < debit_minor:
                    raise InsufficientFunds("insufficient funds")
                self.db.execute("UPDATE accounts SET balance_minor = balance_minor - ? WHERE id=?",
                                (debit_minor, account_id))
                self.db.execute("INSERT INTO approvals_used VALUES (?,?,?)", (nonce, plan_hash, ts))
                cur = self.db.execute(
                    "INSERT INTO payments(ts,owner,plan_hash,account_id,src_ccy,debited_minor,fee_minor,dst_ccy,"
                    "dst_amount_minor,fx_rate,route_id,beneficiary_account,beneficiary_masked,ref_amount_minor,status) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, owner, plan_hash, account_id, src_ccy, debit_minor, fee_minor, dst_ccy, dst_amount_minor,
                     str(fx_rate), route_id, beneficiary_account, beneficiary_masked, ref_amount_minor,
                     "EXECUTED_SANDBOX"))
                self._append_audit(actor, "payment_executed", {
                    "payment_id": cur.lastrowid, "plan_hash": plan_hash, "debited_minor": debit_minor,
                    "src_ccy": src_ccy, "dst_amount_minor": dst_amount_minor, "dst_ccy": dst_ccy,
                    "route": route_id, "beneficiary": beneficiary_masked})
                return {"id": cur.lastrowid, "ts": ts, "plan_hash": plan_hash, "debited_minor": debit_minor,
                        "fee_minor": fee_minor, "src_ccy": src_ccy, "dst_amount_minor": dst_amount_minor,
                        "dst_ccy": dst_ccy, "route_id": route_id, "beneficiary_masked": beneficiary_masked,
                        "status": "EXECUTED_SANDBOX", "duplicate": False}
        except sqlite3.IntegrityError as e:
            raise LedgerError(str(e)) from e
