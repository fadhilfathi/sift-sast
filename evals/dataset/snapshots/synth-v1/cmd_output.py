"""Eval snapshot: cmd output. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import subprocess

def alpha_grep(pattern, logfile):
    return subprocess.check_output(["grep", "-F", pattern, logfile], shell=False)

def beta_grep(pattern, logfile):
    return subprocess.check_output("grep " + pattern + " " + logfile, shell=True)
