"""Eval snapshot: cmd popen. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import shlex
import subprocess

def alpha_preview(path):
    return subprocess.Popen("cat " + path, shell=True).wait()

def beta_preview(path):
    clean = shlex.quote(path)
    return subprocess.run("cat " + clean, shell=True, check=True).returncode
