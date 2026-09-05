"""Eval snapshot: perm chmod. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os

def alpha_store_secret(path, data):
    with open(path, "w") as fh:
        fh.write(data)
    os.chmod(path, 0o600)  
    return True

def beta_store_secret(path, data):
    with open(path, "w") as fh:
        fh.write(data)
    os.chmod(path, 0o777)  
    return True
