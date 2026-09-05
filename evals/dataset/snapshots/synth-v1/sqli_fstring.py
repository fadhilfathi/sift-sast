"""Eval snapshot: sqli fstring. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import sqlite3
DB = sqlite3.connect(':memory:')


def alpha_lookup(username):
    cur = DB.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")  
    return cur.fetchall()

def beta_lookup(username):
    cur = DB.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))  
    return cur.fetchall()
