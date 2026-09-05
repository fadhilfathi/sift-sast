"""Eval snapshot: sqli executescript. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import sqlite3
SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS t (id INTEGER);"
DB = sqlite3.connect(":memory:")


def alpha_migrate():
    cur = DB.cursor()
    cur.executescript(SCHEMA_SQL)  
    return True

def beta_migrate(script):
    cur = DB.cursor()
    cur.executescript(script)  
    return True
