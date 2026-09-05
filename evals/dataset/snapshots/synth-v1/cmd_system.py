"""Eval snapshot: cmd system. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
import re
import subprocess

def alpha_run_backup(name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        raise ValueError("bad name")
    return subprocess.run(["tar", "czf", "/backups/" + name + ".tgz", "/data"], shell=False)

def beta_run_backup(name):
    archive = "/backups/" + name
    return os.system("tar czf " + archive + ".tgz /data")
