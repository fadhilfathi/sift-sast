"""Eval snapshot: marshal loads. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import json
import marshal

def alpha_decode(blob):
    if len(blob) > 4096:
        raise ValueError("too large")
    return json.loads(blob.decode("utf-8"))

def beta_decode(blob):
    return marshal.loads(blob)
