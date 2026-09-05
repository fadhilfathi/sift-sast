"""Eval snapshot: exec controlled. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
MAIN_DB = "/srv/main.db"


def alpha_migrate_db(db_path):
    return os.execv("/usr/bin/sqlite3", ["sqlite3", db_path, ".dump"])

def beta_migrate_db():
    return os.execv("/usr/bin/sqlite3", ["sqlite3", MAIN_DB, ".dump"])
