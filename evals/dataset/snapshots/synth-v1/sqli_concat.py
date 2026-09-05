"""Eval snapshot: sqli concat. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import sqlite3
DB = sqlite3.connect(':memory:')


def alpha_search(term):
    cur = DB.cursor()
    cur.execute("SELECT * FROM docs WHERE body LIKE ?", ("%" + term + "%",))  
    return cur.fetchall()

def beta_search(term):
    cur = DB.cursor()
    cur.execute("SELECT * FROM docs WHERE body LIKE '%" + term + "%'")  
    return cur.fetchall()
