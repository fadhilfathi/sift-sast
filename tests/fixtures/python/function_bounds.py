"""Fixture for function_bounds.scm. Line numbers are asserted exactly."""

import functools


def plain(x):
    return x + 1


@functools.wraps(plain)
def decorated_single(y):
    return y


@functools.wraps(plain)
@functools.lru_cache
def decorated_stacked(z):
    return z


class Widget:
    def method(self, a):
        return a


def outer(n):
    def inner(m):
        return m * 2

    return inner(n)
