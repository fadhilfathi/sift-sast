"""Eval snapshot: yaml load. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import yaml

def alpha_read_conf(text):
    return yaml.load(text)

def beta_read_conf(text):
    return yaml.safe_load(text)
