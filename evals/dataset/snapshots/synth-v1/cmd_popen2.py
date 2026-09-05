"""Eval snapshot: cmd popen2. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os

def alpha_disk_info():
    handle = os.popen("df -h /")
    return handle.read()

def beta_disk_info(spec):
    handle = os.popen("df " + spec)
    return handle.read()
