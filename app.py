#!/usr/bin/env python3
"""
Personal Finance Manager - CLI
Project ID: UY6758GH

Features:
 - User registration & authentication (unique username + password hash)
 - Add / update / delete income & expense entries, categorized
 - Monthly / yearly financial reports (totals & savings)
 - Budgets per-category + notify on exceed
 - SQLite data persistence, backup & restore
 - Simple CLI menu
"""

import sqlite3
import os
import sys
from datetime import datetime, date
import getpass
import hashlib
import secrets
import shutil
import argparse
from typing import Optional, Tuple, List

DB_FILENAME = "pfm.db"
SALT_BYTES = 16
PBKDF2_ITERS = 150_000

# ---------- Database helpers ----------

def get_conn(db_path: str = DB_FILENAME) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DB_FILENAME):
    create = not os.path.exists(db_path)
    conn = get_conn(db_path)
    cur = conn.cursor()
    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    # Categories - user-specific categories are allowed but start with defaults
    cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT NOT NULL,
            UNIQUE(user_id, name),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    # Transactions
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('income','expense')),
            amount REAL NOT NULL CHECK(amount >= 0),
            category_id INTEGER,
            note TEXT,
            occurred_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL
        );
    """)
    # Budgets (monthly budgets per category)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            amount REAL NOT NULL CHECK(amount >= 0),
            month INTEGER NOT NULL, -- 1..12
            year INTEGER NOT NULL,
            UNIQUE(user_id, category_id, month, year),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    if create:
        print(f"[init] Database created at {db_path}")
    conn.close()

# ---------- Security helpers ----------

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS)
    return pw_hash, salt

def verify_password(stored_hash: bytes, stored_salt: bytes, password_attempt: str) -> bool:
    attempt_hash, _ = hash_password(password_attempt, stored_salt)
    return secrets.compare_digest(stored_hash, attempt_hash)

# ---------- User Management ----------

def register(username: str, password: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    created_at = datetime.utcnow().isoformat()
    pw_hash, salt = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, salt, created_at))
        user_id = cur.lastrowid
        # Insert default categories for the new user
        defaults = ["Salary", "Food", "Rent", "Transport", "Entertainment", "Utilities", "Other"]
        for name in defaults:
            cur.execute("INSERT INTO categories (user_id, name) VALUES (?, ?)", (user_id, name))
        conn.commit()
        print(f"[ok] User '{username}' registered.")
        return True
    except sqlite3.IntegrityError:
        print("[error] Username already exists.")
        return False
    finally:
        conn.close()

def login(username: str, password: str) -> Optional[int]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        print("[error] No such user.")
        return None
    if verify_password(row["password_hash"], row["salt"], password):
        print(f"[ok] Logged in as {username}")
        return int(row["id"])
    else:
        print("[error] Incorrect password.")
        return None

# ---------- Category helpers ----------

def add_category(user_id: int, name: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO categories (user_id, name) VALUES (?, ?)", (user_id, name))
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # fetch existing
        cur.execute("SELECT id FROM categories WHERE user_id = ? AND name = ?", (user_id, name))
        row = cur.fetchone()
        return int(row["id"])
    finally:
        conn.close()

def list_categories(user_id: int) -> List[sqlite3.Row]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM categories WHERE user_id = ? ORDER BY name", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------- Transactions ----------

def add_transaction(user_id: int, tx_type: str, amount: float, category: Optional[str], note: Optional[str], occurred_at: Optional[str]) -> int:
    if tx_type not in ("income", "expense"):
        raise ValueError("tx_type must be 'income' or 'expense'")
    if occurred_at is None:
        occurred_at = datetime.utcnow().isoformat()
    conn = get_conn()
    cur = conn.cursor()
    category_id = None
    if category:
        # ensure category exists (create if needed)
        category_id = add_category(user_id, category)
    cur.execute("""
        INSERT INTO transactions (user_id, type, amount, category_id, note, occurred_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, tx_type, float(amount), category_id, note, occurred_at, datetime.utcnow().isoformat()))
    conn.commit()
    tx_id = cur.lastrowid
    conn.close()
    # After adding an expense, check budgets
    if tx_type == "expense" and category_id is not None:
        check_budget_notify(user_id, category_id, occurred_at)
    return tx_id

def update_transaction(user_id: int, tx_id: int, **kwargs) -> bool:
    allowed = {"type", "amount", "category", "note", "occurred_at"}
    updates = {}
    for k, v in kwargs.items():
        if k in allowed and v is not None:
            updates[k] = v
    if not updates:
        return False
    conn = get_conn()
    cur = conn.cursor()
    # fetch transaction and verify ownership
    cur.execute("SELECT id FROM transactions WHERE id = ? AND user_id = ?", (tx_id, user_id))
    if cur.fetchone() is None:
        conn.close()
        return False
    # handle category specially
    if "category" in updates:
        cat_name = updates.pop("category")
        if cat_name is None:
            category_id = None
        else:
            category_id = add_category(user_id, cat_name)
        updates["category_id"] = category_id
    set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
    params = list(updates.values()) + [tx_id]
    cur.execute(f"UPDATE transactions SET {set_clause} WHERE id = ?", params)
    conn.commit()
    conn.close()
    return True

def delete_transaction(user_id: int, tx_id: int) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?", (tx_id, user_id))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed > 0

def list_transactions(user_id: int, limit: int = 50) -> List[sqlite3.Row]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT t.id, t.type, t.amount, c.name as category, t.note, t.occurred_at
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ?
        ORDER BY t.occurred_at DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------- Budgeting ----------

def set_budget(user_id: int, category: str, amount: float, month: int, year: int) -> bool:
    # ensure category exists
    conn = get_conn()
    cur = conn.cursor()
    cat_id = add_category(user_id, category)
    try:
        cur.execute("""
            INSERT INTO budgets (user_id, category_id, amount, month, year)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, category_id, month, year) DO UPDATE SET amount = excluded.amount
        """, (user_id, cat_id, amount, month, year))
        conn.commit()
        return True
    finally:
        conn.close()

def get_budget(user_id: int, category_id: int, month: int, year: int) -> Optional[float]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT amount FROM budgets WHERE user_id = ? AND category_id = ? AND month = ? AND year = ?",
                (user_id, category_id, month, year))
    row = cur.fetchone()
    conn.close()
    return float(row["amount"]) if row else None

def check_budget_notify(user_id: int, category_id: int, occurred_at_iso: str):
    occurred = datetime.fromisoformat(occurred_at_iso)
    month, year = occurred.month, occurred.year
    budget_amount = get_budget(user_id, category_id, month, year)
    if budget_amount is None:
        return
    # compute total expenses for category in month
    conn = get_conn()
    cur = conn.cursor()
    start = date(year, month, 1).isoformat()
    if month == 12:
        end = date(year + 1, 1, 1).isoformat()
    else:
        end = date(year, month + 1, 1).isoformat()
    cur.execute("""
        SELECT SUM(amount) as total FROM transactions
        WHERE user_id = ? AND category_id = ? AND type = 'expense' AND occurred_at >= ? AND occurred_at < ?
    """, (user_id, category_id, start, end))
    row = cur.fetchone()
    conn.close()
    total = float(row["total"]) if row["total"] is not None else 0.0
    if total > budget_amount:
        print(f"[budget alert] You have exceeded your budget for this category this month: {total:.2f} > {budget_amount:.2f}")

# ---------- Reports ----------

def report_monthly(user_id: int, month: int, year: int) -> dict:
    conn = get_conn()
    cur = conn.cursor()
    start = date(year, month, 1).isoformat()
    if month == 12:
        end = date(year + 1, 1, 1).isoformat()
    else:
        end = date(year, month + 1, 1).isoformat()
    cur.execute("""
        SELECT type, SUM(amount) as total FROM transactions
        WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ?
        GROUP BY type
    """, (user_id, start, end))
    rows = cur.fetchall()
    totals = {"income": 0.0, "expense": 0.0}
    for r in rows:
        totals[r["type"]] = float(r["total"])
    # breakdown by category (expenses)
    cur.execute("""
        SELECT c.name, SUM(t.amount) as total
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = ? AND t.type = 'expense' AND t.occurred_at >= ? AND t.occurred_at < ?
        GROUP BY c.name
        ORDER BY total DESC
    """, (user_id, start, end))
    breakdown = [(r["name"] or "Uncategorized", float(r["total"])) for r in cur.fetchall()]
    conn.close()
    totals["savings"] = totals["income"] - totals["expense"]
    return {"period": f"{year}-{month:02d}", "totals": totals, "expense_by_category": breakdown}

def report_yearly(user_id: int, year: int) -> dict:
    conn = get_conn()
    cur = conn.cursor()
    start = date(year, 1, 1).isoformat()
    end = date(year + 1, 1, 1).isoformat()
    cur.execute("""
        SELECT type, SUM(amount) as total FROM transactions
        WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ?
        GROUP BY type
    """, (user_id, start, end))
    rows = cur.fetchall()
    totals = {"income": 0.0, "expense": 0.0}
    for r in rows:
        totals[r["type"]] = float(r["total"])
    totals["savings"] = totals["income"] - totals["expense"]
    conn.close()
    return {"period": str(year), "totals": totals}

# ---------- Backup & Restore ----------

def backup_db(backup_path: str):
    if not os.path.exists(DB_FILENAME):
        raise FileNotFoundError("Database file not found.")
    shutil.copy2(DB_FILENAME, backup_path)
    print(f"[ok] Backup written to {backup_path}")

def restore_db(backup_path: str):
    if not os.path.exists(backup_path):
        raise FileNotFoundError("Backup file not found.")
    shutil.copy2(backup_path, DB_FILENAME)
    print(f"[ok] Database restored from {backup_path}")

# ---------- CLI ----------

def prompt_password(prompt_text="Password: ") -> str:
    return getpass.getpass(prompt_text)

def run_cli():
    init_db()
    current_user = None
    current_user_id = None

    def require_login():
        if current_user_id is None:
            print("[error] You must log in first.")
            return False
        return True

    while True:
        print("\n=== Personal Finance Manager ===")
        print("1) Register")
        print("2) Login")
        print("3) Add transaction")
        print("4) Update transaction")
        print("5) Delete transaction")
        print("6) List recent transactions")
        print("7) Set budget")
        print("8) Monthly report")
        print("9) Yearly report")
        print("10) Backup DB")
        print("11) Restore DB")
        print("12) List categories")
        print("0) Exit")
        choice = input("Choose an option: ").strip()
        try:
            if choice == "1":
                uname = input("Choose username: ").strip()
                pw = input("Choose password: ").strip()

                register(uname, pw)
            elif choice == "2":
                uname = input("Username: ").strip()
                pw = input("Password: ").strip()

                uid = login(uname, pw)
                if uid:
                    current_user = uname
                    current_user_id = uid
            elif choice == "3":
                if not require_login(): continue
                ttype = input("Type (income/expense): ").strip().lower()
                amt = float(input("Amount: ").strip())
                cat = input("Category (leave blank for Uncategorized): ").strip() or None
                note = input("Note (optional): ").strip() or None
                date_input = input("Date (YYYY-MM-DD or leave blank for today): ").strip()
                occurred = None
                if date_input:
                    try:
                        # Simple validation
                        occurred = datetime.fromisoformat(date_input).isoformat()
                    except Exception:
                        print("[error] Invalid date format. Use YYYY-MM-DD")
                        continue
                tx_id = add_transaction(current_user_id, ttype, amt, cat, note, occurred)
                print(f"[ok] Transaction added (id={tx_id})")
            elif choice == "4":
                if not require_login(): continue
                tx_id = int(input("Transaction id to update: ").strip())
                print("Leave fields blank to keep current.")
                ttype = input("Type (income/expense): ").strip() or None
                amt_raw = input("Amount: ").strip() or None
                amt = float(amt_raw) if amt_raw else None
                cat = input("Category: ").strip() or None
                note = input("Note: ").strip() or None
                date_input = input("Date (YYYY-MM-DD): ").strip() or None
                occurred = datetime.fromisoformat(date_input).isoformat() if date_input else None
                ok = update_transaction(current_user_id, tx_id,
                                        type=ttype, amount=amt, category=cat, note=note, occurred_at=occurred)
                print("[ok] Updated." if ok else "[error] Update failed.")
            elif choice == "5":
                if not require_login(): continue
                tx_id = int(input("Transaction id to delete: ").strip())
                if delete_transaction(current_user_id, tx_id):
                    print("[ok] Deleted.")
                else:
                    print("[error] Delete failed.")
            elif choice == "6":
                if not require_login(): continue
                rows = list_transactions(current_user_id, limit=50)
                print("Recent transactions:")
                for r in rows:
                    print(f" id={r['id']:>3} | {r['type']:7} | {r['amount']:8.2f} | {r['category'] or 'Uncat':12} | {r['occurred_at'][:10]} | {r['note'] or ''}")
            elif choice == "7":
                if not require_login(): continue
                cat = input("Category: ").strip()
                amount = float(input("Monthly budget amount: ").strip())
                month = int(input("Month (1-12): ").strip())
                year = int(input("Year (e.g. 2025): ").strip())
                set_budget(current_user_id, cat, amount, month, year)
                print("[ok] Budget set.")
            elif choice == "8":
                if not require_login(): continue
                month = int(input("Month (1-12): ").strip())
                year = int(input("Year (e.g. 2025): ").strip())
                rpt = report_monthly(current_user_id, month, year)
                print(f"Report for {rpt['period']}:")
                print(f"  Income:  {rpt['totals']['income']:.2f}")
                print(f"  Expense: {rpt['totals']['expense']:.2f}")
                print(f"  Savings: {rpt['totals']['savings']:.2f}")
                print("  Expenses by category:")
                for name, tot in rpt["expense_by_category"]:
                    print(f"    {name or 'Uncategorized'}: {tot:.2f}")
            elif choice == "9":
                if not require_login(): continue
                year = int(input("Year (e.g. 2025): ").strip())
                rpt = report_yearly(current_user_id, year)
                print(f"Report for {rpt['period']}:")
                print(f"  Income:  {rpt['totals']['income']:.2f}")
                print(f"  Expense: {rpt['totals']['expense']:.2f}")
                print(f"  Savings: {rpt['totals']['savings']:.2f}")
            elif choice == "10":
                path = input("Backup path (e.g. backup_pf.db): ").strip()
                backup_db(path)
            elif choice == "11":
                path = input("Backup file to restore: ").strip()
                confirm = input("This will overwrite current DB. Continue? (yes/no): ").strip().lower()
                if confirm == "yes":
                    restore_db(path)
                    # Re-init to ensure schema intact
                    init_db()
            elif choice == "12":
                if not require_login(): continue
                cats = list_categories(current_user_id)
                print("Categories:")
                for c in cats:
                    print(f"  [{c['id']}] {c['name']}")
            elif choice == "0":
                print("Goodbye.")
                break
            else:
                print("[error] Unknown option.")
        except Exception as exc:
            print("[error] An error occurred:", str(exc))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Personal Finance Manager (CLI)")
    parser.add_argument("--init", action="store_true", help="Initialize the database (create schema).")
    parser.add_argument("--run", action="store_true", help="Run CLI.")
    args = parser.parse_args()

    if args.init:
        init_db()
        sys.exit(0)
    if args.run:
        run_cli()
    else:
        # default: run CLI
        run_cli()
