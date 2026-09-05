"""Eval snapshot: zip extract. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
import zipfile

def alpha_unzip(archive, dest):
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)

def beta_unzip(archive, dest):
    with zipfile.ZipFile(archive) as zf:
        for member in zf.namelist():
            target = os.path.realpath(os.path.join(dest, member))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise ValueError("zip slip: " + member)
        zf.extractall(dest)
