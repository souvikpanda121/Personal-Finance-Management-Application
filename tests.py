import unittest
import os
import tempfile
import shutil
from app import init_db, get_conn, register, login, add_transaction, list_transactions, set_budget, report_monthly, backup_db, restore_db, DB_FILENAME

class TestPFM(unittest.TestCase):
    def setUp(self):
        # create a temporary directory and DB path
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "pfm_test.db")
        # create DB
        init_db(self.db_path)
        # monkeypatch DB_FILENAME for the backup functions if needed
        self.orig_db = DB_FILENAME
        # ensure functions use our db path by setting environment or replacing module variable
        # simplest: copy init_db-created db to default name and work there
        shutil.copy2(self.db_path, DB_FILENAME)

    def tearDown(self):
        try:
            os.remove(DB_FILENAME)
        except Exception:
            pass
        shutil.rmtree(self.tmpdir)

    def test_register_and_login(self):
        ok = register("testuser", "pass123")
        self.assertTrue(ok)
        uid = login("testuser", "pass123")
        self.assertIsNotNone(uid)

    def test_transactions_and_reports(self):
        register("t2", "p")
        uid = login("t2", "p")
        # add income
        add_transaction(uid, "income", 1000.0, "Salary", "monthly salary", None)
        # add expenses
        add_transaction(uid, "expense", 200.0, "Food", "groceries", None)
        add_transaction(uid, "expense", 300.0, "Rent", "apartment", None)
        # monthly report for current month
        today = __import__("datetime").datetime.utcnow()
        rpt = report_monthly(uid, today.month, today.year)
        self.assertAlmostEqual(rpt["totals"]["income"], 1000.0)
        self.assertAlmostEqual(rpt["totals"]["expense"], 500.0)
        self.assertAlmostEqual(rpt["totals"]["savings"], 500.0)

    def test_budget_notification(self):
        register("t3", "p")
        uid = login("t3", "p")
        # set budget low
        set_budget(uid, "Food", 50.0, 1, 2050)  # future month so won't trigger
        # set budget for this month:
        today = __import__("datetime").datetime.utcnow()
        set_budget(uid, "Food", 100.0, today.month, today.year)
        # add expense that exceeds the budget
        add_transaction(uid, "expense", 120.0, "Food", "big meal", today.isoformat())
        # nothing to assert here except no exceptions

    def test_backup_restore(self):
        register("buser", "p")
        uid = login("buser", "p")
        add_transaction(uid, "income", 50.0, "Other", None, None)
        backup_file = os.path.join(self.tmpdir, "bk.db")
        backup_db(backup_file)
        # delete current DB and restore
        os.remove(DB_FILENAME)
        restore_db(backup_file)
        # now login should still work
        uid2 = login("buser", "p")
        self.assertIsNotNone(uid2)

if __name__ == "__main__":
    unittest.main()
