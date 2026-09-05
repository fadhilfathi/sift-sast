"""Eval snapshot: path delete. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import os
CACHE = '/srv/cache'
KNOWN_KEYS = frozenset({'a', 'b'})


def alpha_remove_cache(key):
    if key not in KNOWN_KEYS:
        raise KeyError(key)
    os.remove(os.path.join(CACHE, key))  
    return True

def beta_remove_cache(key):
    os.remove(os.path.join(CACHE, key))  
    return True
