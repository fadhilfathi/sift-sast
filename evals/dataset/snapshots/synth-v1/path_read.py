"""Eval snapshot: path read. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
ARTICLES = "/srv/articles"


def alpha_show_article(slug):
    target = os.path.realpath(os.path.join(ARTICLES, slug))
    if not target.startswith(os.path.realpath(ARTICLES) + os.sep):
        raise ValueError("outside root")
    with open(target) as fh:
        return fh.read()

def beta_show_article(slug):
    with open(os.path.join(ARTICLES, slug)) as fh:
        return fh.read()
