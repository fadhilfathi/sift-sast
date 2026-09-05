"""Eval snapshot: regex dos. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import re

def alpha_find(data):
    return re.search(r"[A-Za-z0-9_]{1,64}", data)

def beta_find(data, pattern):
    return re.search(pattern, data)
