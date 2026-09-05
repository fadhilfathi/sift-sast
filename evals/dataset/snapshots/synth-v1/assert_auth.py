"""Eval snapshot: assert auth. Two variants of the same sink; labels live in dataset.jsonl, never here."""
def run_admin_task():
    return 'done'


def alpha_admin_action(user):
    if not user.is_admin:
        raise PermissionError("admin required")  
    return run_admin_task()

def beta_admin_action(user):
    assert user.is_admin  
    return run_admin_task()
