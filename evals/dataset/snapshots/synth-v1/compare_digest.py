"""Eval snapshot: compare digest. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import hmac

def alpha_verify(provided, actual):
    return hmac.compare_digest(provided, actual)

def beta_verify(provided, actual):
    return provided == actual
