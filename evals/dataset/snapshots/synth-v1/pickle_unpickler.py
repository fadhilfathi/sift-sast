"""Eval snapshot: pickle unpickler. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import hashlib
import hmac
import pickle
EXPECTED_DIGEST = "0" * 64


def alpha_load_session(path):
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if not hmac.compare_digest(digest, EXPECTED_DIGEST):
        raise ValueError("untrusted session file")
    with open(path, "rb") as fh:
        return pickle.Unpickler(fh).load()

def beta_load_session(path):
    with open(path, "rb") as fh:
        return pickle.Unpickler(fh).load()
