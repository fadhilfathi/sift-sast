"""Eval snapshot: cors wildcard. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import json
class Response:
    def __init__(self, body, headers=None, status=200):
        self.body = body
        self.headers = headers or {}
        self.status = status


def alpha_api_response(payload):
    return Response(json.dumps(payload), headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})

def beta_api_response(payload):
    return Response(json.dumps(payload), headers={"Access-Control-Allow-Origin": "https://app.example"})
