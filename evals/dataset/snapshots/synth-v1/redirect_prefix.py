"""Eval snapshot: redirect prefix. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import urllib.parse
class Response:
    def __init__(self, body=b'', headers=None, status=200):
        self.body = body
        self.headers = headers or {}
        self.status = status


def alpha_docs(page):
    return Response(status=302, headers={"Location": "/docs/" + page})

def beta_docs(page):
    return Response(status=302, headers={"Location": "/docs/" + urllib.parse.quote(page, safe="")})
