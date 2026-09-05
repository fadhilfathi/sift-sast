"""Eval snapshot: rng token. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import random
import secrets

def alpha_make_otp():
    return str(random.randint(100000, 999999))

def beta_make_otp():
    return str(secrets.randbelow(900000) + 100000)
