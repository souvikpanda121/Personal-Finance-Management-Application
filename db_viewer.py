import sqlite3

conn = sqlite3.connect("pfm.db")
cursor = conn.cursor()

print("\n=== Users ===")
cursor.execute("SELECT * FROM users;")
for row in cursor.fetchall():
    print(row)

print("\n=== Categories ===")
cursor.execute("SELECT * FROM categories;")
for row in cursor.fetchall():
    print(row)

print("\n=== Transactions ===")
cursor.execute("SELECT * FROM transactions;")
for row in cursor.fetchall():
    print(row)

print("\n=== Budgets ===")
cursor.execute("SELECT * FROM budgets;")
for row in cursor.fetchall():
    print(row)

conn.close()
