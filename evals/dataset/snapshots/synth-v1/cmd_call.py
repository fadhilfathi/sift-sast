"""Eval snapshot: cmd call. Two variants of the same sink; labels live in dataset.jsonl, never here."""
import ipaddress
import subprocess

def alpha_ping(host):
    addr = ipaddress.ip_address(host)
    return subprocess.call(["ping", "-c1", str(addr)], shell=False)

def beta_ping(host):
    return subprocess.call("ping -c1 %s" % host, shell=True)
