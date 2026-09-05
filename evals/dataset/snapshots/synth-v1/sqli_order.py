"""Eval snapshot: sqli order. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import sqlite3
DB = sqlite3.connect(':memory:')


def alpha_list_users(order):
    cur = DB.cursor()
    cur.execute("SELECT * FROM users ORDER BY " + order)  
    return cur.fetchall()

def beta_list_users(order):
    if order not in ("name", "id", "created"):
        raise ValueError("bad column")
    cur = DB.cursor()
    cur.execute("SELECT * FROM users ORDER BY " + order)  
    return cur.fetchall()
