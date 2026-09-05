"""The P4 eval harness.

Config stamping, cost estimation, the pre-call budget guard, and the dataset
loader. Deliberately does not contain the four agents (P5) or the naive
baseline's prompt (P4 step 5) — this package is scaffolding those steps build
on, not the steps themselves.
"""
