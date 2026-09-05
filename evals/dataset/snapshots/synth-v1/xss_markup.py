"""Eval snapshot: xss markup. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import markupsafe
from markupsafe import Markup


def alpha_greet(name):
    return "<h1>Hello " + str(markupsafe.escape(name)) + "</h1>"

def beta_greet(name):
    return "<h1>Hello " + str(Markup(name)) + "</h1>"
