import os, sqlite3

for root, dirs, files in os.walk('dataset/evidence'):
    for f in files:
        if f.endswith('.sql'):
            p = os.path.join(root, f)
            try:
                con = sqlite3.connect(':memory:')
                con.executescript(open(p, encoding='utf-8').read())
                cur = con.cursor()
                tables = [t[0] for t in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                for table in tables:
                    for row in cur.execute(f"SELECT * FROM {table}").fetchall():
                        s = str(row)
                        if '6645' in s or '5569' in s:
                            print(p, table, row)
            except Exception as e:
                pass
