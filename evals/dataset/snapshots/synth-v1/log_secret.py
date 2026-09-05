"""Eval snapshot: log secret. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import logging
logger = logging.getLogger(__name__)
class backend:
    @staticmethod
    def check(u, p):
        return True


def alpha_sign_in(username, password):
    logger.info("login attempt for %s with password %s", username, password)  
    return backend.check(username, password)

def beta_sign_in(username, password):
    logger.info("login attempt for %s", username)  
    return backend.check(username, password)
