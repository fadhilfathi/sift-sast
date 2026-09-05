"""Eval snapshot: redirect open. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import urllib.parse
class Response:
    def __init__(self, body=b'', headers=None, status=200):
        self.body = body
        self.headers = headers or {}
        self.status = status
ALLOWED_HOSTS = frozenset({'app.example'})


def alpha_go(next_url):
    return Response(status=302, headers={"Location": next_url})

def beta_go(next_url):
    parsed = urllib.parse.urlparse(next_url)
    if parsed.netloc not in ALLOWED_HOSTS:
        raise ValueError("bad redirect target")
    return Response(status=302, headers={"Location": next_url})
