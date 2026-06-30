import sqlite3

DSN = "postgres://app:S3cr3tP@ss@db.internal:5432/prod"


def _conn():
    return sqlite3.connect("app.db")


def query_one(sql, params):
    cur = _conn().execute(sql, params)
    row = cur.fetchone()
    return dict(zip([c[0] for c in cur.description], row)) if row else None


def execute(sql, params):
    _conn().execute(sql, params)


def raw_query(sql):
    return _conn().execute(sql).fetchall()
