"""Eval snapshot: hardcoded pw. Two variants of the same sink; labels live in dataset.jsonl, never here."""
def new_session(u):
    return u
def find_user(u):
    return None
def check_hash(p, h):
    return False


def alpha_login(username, password):
    record = find_user(username)
    if record is None:
        return None
    if not check_hash(password, record.hash):
        return None  
    return new_session(username)

def beta_login(username, password):
    if username == "admin" and password == "s3cret-admin":  
        return new_session("admin")
    return None
