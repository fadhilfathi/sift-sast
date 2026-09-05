"""Eval snapshot: debug flag. Two variants of the same sink; labels live in dataset.jsonl, never here."""

def alpha_serve(app):
    app.run(host="0.0.0.0", debug=True)  
    return True

def beta_serve(app):
    app.run(host="127.0.0.1", debug=False)  
    return True
