"""Canonicalization for the lossless round-trip contract.

Lossless means *semantic* equality of the parsed documents, not byte-identity.
The rules are specified in `docs/ARCHITECTURE.md` (decision D2); this module is
the executable version of them.

Byte-identity is not the target because it is not achievable: JSON key order is
not semantic, encoders differ on unicode escaping and number formatting, and
real scanner output contains constructs the official schema rejects. A check
that cannot hold is a check someone later relaxes, and relaxing a check to make
it pass is forbidden.

What *is* significant, and what this module is careful to preserve:

- absent, ``null``, and empty are three distinct states
- array order, everywhere
- unknown keys, at every nesting depth
"""

from __future__ import annotations

import json
from typing import Any

#: Beyond this, IEEE 754 doubles cannot represent consecutive integers, so an
#: integral float can no longer be assumed to have come from an integer.
_MAX_EXACT_INT = 2**53


def canonical(value: Any) -> Any:
    """Normalize a parsed JSON document for comparison.

    Only numbers are rewritten. Everything else is returned structurally
    unchanged, so a difference that survives this function is a real difference.
    """
    if isinstance(value, bool):
        # Must precede the int branch: bool is a subclass of int in Python, and
        # collapsing True to 1 would make a boolean flag compare equal to a count.
        return value
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [canonical(v) for v in value]
    return value


def _canonical_float(value: float) -> float | int:
    """Collapse an integral float to an int, where that is lossless.

    JSON has a single number type, so ``8`` and ``8.0`` are the same value and
    encoders disagree about which to emit. Above 2**53 the collapse would not be
    lossless, and ``-0.0`` is left alone because it is distinguishable from 0.
    """
    if value != value or value in (float("inf"), float("-inf")):  # NaN or infinity
        return value
    if not value.is_integer():
        return value
    if abs(value) >= _MAX_EXACT_INT:
        return value
    if value == 0.0 and str(value)[0] == "-":  # negative zero
        return value
    return int(value)


def canonical_equal(left: Any, right: Any) -> bool:
    """True when two parsed JSON documents are semantically equal.

    Deliberately not ``canonical(a) == canonical(b)``. Python's ``bool`` is a
    subclass of ``int``, so ``True == 1`` and ``False == 0``, and a plain
    comparison would report a JSON ``true`` and a JSON ``1`` as the same value.
    :func:`diff` already compares types strictly, so equality is defined as
    "no differences" and there is one implementation rather than two that can
    drift apart.
    """
    return not diff(left, right)


def dumps(document: Any, *, indent: int | None = 2) -> str:
    """Serialize with the settings the emitter uses.

    ``ensure_ascii=False`` keeps non-ASCII paths readable rather than escaping
    them, and ``sort_keys`` is deliberately off: key order is not semantic, so
    reordering someone's document would be a gratuitous diff.
    """
    return json.dumps(document, indent=indent, ensure_ascii=False)


def diff(left: Any, right: Any, path: str = "") -> list[str]:
    """Human-readable differences, for test failure output.

    A bare ``assert a == b`` on two large SARIF documents produces output nobody
    can read. This names the JSON pointer of each divergence instead.
    """
    left, right = canonical(left), canonical(right)
    return list(_diff(left, right, path))


def _diff(left: Any, right: Any, path: str) -> Any:
    at = path or "/"
    if type(left) is not type(right):
        yield f"{at}: type {type(left).__name__} -> {type(right).__name__}"
        return
    if isinstance(left, dict):
        for key in left.keys() | right.keys():
            if key not in left:
                yield f"{path}/{key}: ADDED {right[key]!r}"
            elif key not in right:
                yield f"{path}/{key}: LOST {left[key]!r}"
            else:
                yield from _diff(left[key], right[key], f"{path}/{key}")
    elif isinstance(left, list):
        if len(left) != len(right):
            yield f"{at}: length {len(left)} -> {len(right)}"
        for i, (a, b) in enumerate(zip(left, right, strict=False)):
            yield from _diff(a, b, f"{path}/{i}")
    elif left != right:
        yield f"{at}: {left!r} -> {right!r}"
