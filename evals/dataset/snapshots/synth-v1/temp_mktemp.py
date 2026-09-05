"""Eval snapshot: temp mktemp. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
import tempfile

def alpha_stage(data):
    path = tempfile.mktemp(prefix="stage")
    with open(path, "wb") as fh:
        fh.write(data)  
    return path

def beta_stage(data):
    fd, path = tempfile.mkstemp(prefix="stage")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)  
    return path
