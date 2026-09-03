"""Redaction — decision D8, tested in both directions.

Direction one: the raw value must never survive anywhere in the output.
Direction two: what remains must still let the model describe the finding.
"""

from __future__ import annotations

from sift.context.redact import find_secrets, redact_span, redact_text
from sift.models.context import CodeSpan, EntropyClass, SecretKind

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImpvaG4ifQ."
    "dQw4w9WgXcQ_examplesignature123456"
)
CONNECTION_STRING = "postgres://admin:sup3rSecr3t@db.internal:5432/prod"
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAK...redactme...QIDAQAB\n"
    "-----END RSA PRIVATE KEY-----"
)
GENERIC_HIGH = "kJ8#mP2$xL9@vQ4!nR7&wZ1*bT6^"


# ----------------------------------------------------- direction 1: the value is gone


def test_aws_key_is_never_in_the_output() -> None:
    text, _ = redact_text(f'AWS_KEY = "{AWS_KEY}"')
    assert AWS_KEY not in text


def test_jwt_is_never_in_the_output() -> None:
    text, _ = redact_text(f'token = "{JWT}"')
    assert JWT not in text


def test_connection_string_is_never_in_the_output() -> None:
    text, _ = redact_text(f'DSN = "{CONNECTION_STRING}"')
    assert CONNECTION_STRING not in text
    assert "sup3rSecr3t" not in text


def test_private_key_is_never_in_the_output() -> None:
    text, _ = redact_text(PEM)
    assert "MIIBOgIBAAJBAK" not in text
    assert "-----BEGIN" not in text


def test_generic_high_entropy_literal_is_never_in_the_output() -> None:
    text, _ = redact_text(f'secret = "{GENERIC_HIGH}"')
    assert GENERIC_HIGH not in text


def test_placeholder_contains_no_substring_of_the_secret_longer_than_trivial() -> None:
    """Guards against a redaction that keeps a damaging prefix or suffix."""
    text, _ = redact_text(f'AWS_KEY = "{AWS_KEY}"')
    for length in (4, 6, 8):
        for i in range(len(AWS_KEY) - length):
            assert AWS_KEY[i : i + length] not in text


def test_redact_span_never_leaks_into_the_new_span() -> None:
    span = CodeSpan(path="src/config.py", start_line=1, end_line=1, source=f'AWS_KEY = "{AWS_KEY}"')
    new_span, secrets = redact_span(span)
    assert AWS_KEY not in new_span.source
    assert AWS_KEY not in new_span.as_untrusted_block()
    assert len(secrets) == 1


def test_no_hash_of_the_value_is_computed_or_stored() -> None:
    """RedactedSecret's own field set is the enforcement; see test_context_schema.

    Reasserted here against the actual redaction output: the placeholder text
    itself must not contain anything that looks like a hash of the value.
    """
    import hashlib

    text, _ = redact_text(f'AWS_KEY = "{AWS_KEY}"')
    digest = hashlib.sha256(AWS_KEY.encode()).hexdigest()
    assert digest not in text
    assert digest[:12] not in text


# --------------------------------------------- direction 2: still describable


def test_redacted_aws_key_is_still_describable() -> None:
    """Kind, length, and location survive.

    Not entropy_class: AWS's fixed 16-char suffix caps Shannon entropy at
    exactly log2(16) bits regardless of content, so whether one specific real
    key lands MEDIUM or HIGH is a fact about its characters, not a bug. The
    entropy-bucket boundaries themselves are tested directly in
    test_context_schema.py against strings chosen to sit clearly in each
    bucket, rather than pinned to this AWS-shaped example.
    """
    span = CodeSpan(path="src/config.py", start_line=3, end_line=3, source=f'AWS_KEY = "{AWS_KEY}"')
    new_span, secrets = redact_span(span)
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.kind is SecretKind.AWS_ACCESS_KEY
    assert secret.length == len(AWS_KEY)
    assert secret.entropy_class in set(EntropyClass)
    assert secret.location.line == 3
    assert "kind=aws_access_key" in new_span.source
    assert f"len={len(AWS_KEY)}" in new_span.source


def test_the_placeholder_survives_into_the_untrusted_block() -> None:
    """The evidence must reach the model, through the only channel it may use."""
    span = CodeSpan(path="a.py", start_line=1, end_line=1, source=f'x = "{AWS_KEY}"')
    new_span, _ = redact_span(span)
    assert "REDACTED:kind=aws_access_key" in new_span.as_untrusted_block()


def test_location_accounts_for_lines_before_the_match() -> None:
    source = f'a = 1\nb = 2\nAWS_KEY = "{AWS_KEY}"\n'
    span = CodeSpan(path="a.py", start_line=10, end_line=12, source=source)
    _, secrets = redact_span(span)
    assert secrets[0].location.line == 12  # start_line(10) + 2 lines before the match


# ----------------------------------------------------------- precision


def test_ordinary_code_is_not_redacted() -> None:
    text, matches = redact_text(
        "def handler(request):\n    return render_template('index.html', title='Welcome')\n"
    )
    assert matches == []
    assert "REDACTED" not in text


def test_short_string_is_not_flagged_generic() -> None:
    _text, matches = redact_text('name = "hello world this is fine"')
    assert matches == []


def test_specific_pattern_wins_over_generic_when_both_could_match() -> None:
    matches = find_secrets(f'"{AWS_KEY}"')
    assert len(matches) == 1
    assert matches[0][2] is SecretKind.AWS_ACCESS_KEY


def test_multiple_distinct_secrets_in_one_span_are_all_caught() -> None:
    source = f'AWS_KEY = "{AWS_KEY}"\nDSN = "{CONNECTION_STRING}"\n'
    text, matches = redact_text(source)
    kinds = {m[0][2] for m in matches}
    assert kinds == {SecretKind.AWS_ACCESS_KEY, SecretKind.CONNECTION_STRING}
    assert AWS_KEY not in text
    assert "sup3rSecr3t" not in text
