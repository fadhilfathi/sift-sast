"""Eval snapshot: path write. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
import re
UPLOADS = "/srv/uploads"


def alpha_save_upload(filename, data):
    with open(UPLOADS + "/" + filename, "wb") as fh:
        fh.write(data)  
    return True

def beta_save_upload(filename, data):
    safe = os.path.basename(filename)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", safe):
        raise ValueError("bad filename")
    with open(os.path.join(UPLOADS, safe), "wb") as fh:
        fh.write(data)  
    return True
