"""Eval snapshot: broad except. Two variants of the same sink; labels live in dataset.jsonl, never here."""
class backend:
    @staticmethod
    def check(u, p):
        return True


def alpha_authenticate(username, password):
    try:
        return backend.check(username, password)
    except ConnectionError:
        raise

def beta_authenticate(username, password):
    try:
        return backend.check(username, password)  
    except Exception:
        return None
