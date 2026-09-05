"""Eval snapshot: hash md5. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import hashlib

def alpha_checksum_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        digest.update(fh.read())
    return digest.hexdigest()

def beta_check_password(password, expected):
    return hashlib.md5(password.encode()).hexdigest() == expected
