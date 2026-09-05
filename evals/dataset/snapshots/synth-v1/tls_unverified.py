"""Eval snapshot: tls unverified. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import ssl
import urllib.request

def alpha_fetch(url):
    ctx = ssl.create_default_context()
    return urllib.request.urlopen(url, context=ctx).read()

def beta_fetch(url):
    ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(url, context=ctx).read()
