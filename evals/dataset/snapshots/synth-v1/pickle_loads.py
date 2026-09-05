"""Eval snapshot: pickle loads. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import json
import pickle

def alpha_restore(blob):
    return json.loads(blob.decode("utf-8"))

def beta_restore(blob):
    return pickle.loads(blob)
