"""Fixture for calls.scm, including the DYNAMIC_CALL_NAMES cases."""

import os
import subprocess


def static_calls(cmd):
    subprocess.check_output(cmd)
    return len(cmd)


def dynamic_dispatch(name, cmd):
    fn = getattr(os, name)
    return fn(cmd)


def uncapturable_target(factory, x):
    # Calling the result of another call: no static name exists for this,
    # and the query must not invent one.
    return factory(x)()
