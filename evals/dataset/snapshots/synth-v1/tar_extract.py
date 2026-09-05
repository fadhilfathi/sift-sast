"""Eval snapshot: tar extract. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import tarfile

def alpha_unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")

def beta_unpack(archive, dest):
    with tarfile.open(archive) as tar:
        tar.extractall(dest)
