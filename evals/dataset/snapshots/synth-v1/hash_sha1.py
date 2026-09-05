"""Eval snapshot: hash sha1. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import hashlib
import secrets

def alpha_token(user_id):
    return hashlib.sha1(("reset:" + user_id).encode()).hexdigest()

def beta_token():
    return secrets.token_urlsafe(32)
