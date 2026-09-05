"""Eval snapshot: cmd executable. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import subprocess

def alpha_convert(infile):
    return subprocess.run(["/usr/bin/convert", infile], shell=False).returncode

def beta_convert(tool, infile):
    return subprocess.run([tool, infile], shell=False).returncode
