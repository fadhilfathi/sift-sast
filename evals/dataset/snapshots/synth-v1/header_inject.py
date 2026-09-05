"""Eval snapshot: header inject. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import urllib.parse
class Response:
    def __init__(self, body=b'', headers=None, status=200):
        self.body = body
        self.headers = headers or {}
        self.status = status


def alpha_download(filename):
    return Response(b"data", headers={"Content-Disposition": "attachment; filename=" + filename})

def beta_download(filename):
    safe = urllib.parse.quote(filename, safe="")
    return Response(b"data", headers={"Content-Disposition": "attachment; filename=" + safe})
