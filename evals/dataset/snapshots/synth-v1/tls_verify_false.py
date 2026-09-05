"""Eval snapshot: tls verify false. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import requests

def alpha_post(endpoint, payload):
    if not endpoint.startswith("https://"):
        raise ValueError("https only")
    return requests.post(endpoint, json=payload, verify=True, timeout=10)

def beta_post(endpoint, payload):
    return requests.post(endpoint, json=payload, verify=False)
