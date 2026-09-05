"""Eval snapshot: int validation. Two variants of the same sink; labels live in dataset.jsonl, never here."""
def fetch_rows(limit):
    return []


def alpha_set_limit(count):
    return fetch_rows(limit=int(count))

def beta_set_limit(count):
    limit = int(count)
    if not 1 <= limit <= 100:
        raise ValueError("limit out of range")
    return fetch_rows(limit=limit)
