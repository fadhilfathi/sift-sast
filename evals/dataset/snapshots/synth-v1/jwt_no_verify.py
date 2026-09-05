"""Eval snapshot: jwt no verify. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import jwt
PUBLIC_KEY = 'not-a-real-key'


def alpha_current_user(token):
    claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])  
    return claims.get("sub")

def beta_current_user(token):
    claims = jwt.decode(token, options={"verify_signature": False})  
    return claims.get("sub")
