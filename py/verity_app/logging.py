"""Logging that cannot leak a secret, because the only way to log one is to fingerprint it.

Mirrors ``ts/src/logging.ts``. The fingerprint construction is part of the cross-language contract —
``test-vectors/parity.json`` pins it — because an operator comparing a key fingerprint across a
TypeScript app and a Python one must be comparing the same function.

Why this module exists at all
-----------------------------
``app-compose.json`` sets ``public_logs``, and it commonly defaults to **true**: container stdout is
retrievable by anyone who can reach the CVM's log endpoint. A key printed here is a key published.

That is not hypothetical. During the experiment that produced this guidance, a KMS-derived private
key was printed into public logs by someone who had *already designed the final test to avoid
exactly that* — the leak happened in an earlier discovery run where the value was "just being
checked". Knowing the rule is demonstrably not enough, so the safe thing is made the only convenient
thing.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final, Literal

FingerprintDomain = Literal[
    "derived-key",
    "holder-signature",
    "migration-nonce",
    "export-key",
    "instance-secret",
]

_DOMAINS: Final[frozenset[str]] = frozenset(
    {"derived-key", "holder-signature", "migration-nonce", "export-key", "instance-secret"}
)


class SecretInLogError(Exception):
    """Raised instead of printing something that looks like a secret."""

    def __init__(self, shape: str) -> None:
        super().__init__(
            f"refusing to log a value matching {shape}. "
            "Log fingerprint(domain, secret) instead — see verity_app/logging.py."
        )
        self.shape = shape


def fingerprint(domain: FingerprintDomain, secret: str | bytes) -> str:
    """A short, domain-separated digest of a secret.

    Comparable across time and across instances; not reversible, and not comparable across domains.

    **Domain separation is not decoration.** Without it, a fingerprint over a migration nonce and
    one
    over a signing key are the same function of the same bytes, so a value logged in a harmless
    context confirms a guess about a value in a sensitive one.

    Truncated to 16 hex characters: enough that an accidental collision between two different keys
    does not happen, short enough to read in a log line. A full digest gets treated as noise and
    skipped, which is its own kind of failure.
    """
    if domain not in _DOMAINS:
        raise ValueError(f"unknown fingerprint domain {domain!r}; domains are a closed set")
    digest = hashlib.sha256()
    digest.update(f"verity-fp|{domain}|".encode())
    digest.update(secret.encode() if isinstance(secret, str) else secret)
    return digest.hexdigest()[:16]


# Content shapes that are unambiguously secret wherever they appear.
#
# Deliberately **not** including bare 64-character hex. A bytes32 is that shape and so is a private
# key; the string alone cannot separate them. Refusing all of them would block compose hashes,
# instance ids and digests — the values an operational log most needs — and a checker that fires on
# ordinary data is a checker someone removes. Field names carry that distinction instead.
_SECRET_SHAPES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("PEM private key", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("mnemonic-like phrase", re.compile(r"\b(?:[a-z]{3,8}\s+){11,}[a-z]{3,8}\b")),
)

# The ``_fp`` suffix is the sanctioned escape, and the only one: ``key_fp`` passes, ``key`` does
# not.
# The safe spelling is one character longer than the unsafe one, and the unsafe one fails in a test.
_SUSPICIOUS_WORDS: Final[frozenset[str]] = frozenset(
    {
        "key",
        "keys",
        "secret",
        "private",
        "privkey",
        "apikey",
        "passphrase",
        "password",
        "credential",
        "credentials",
        "seed",
        "mnemonic",
        "token",
        "pem",
        "entropy",
    }
)

_WORD_SPLIT: Final[re.Pattern[str]] = re.compile(r"[\s_\-.]+")
_CAMEL_BOUNDARY: Final[re.Pattern[str]] = re.compile(r"([a-z0-9])([A-Z])")


def _words(field: str) -> list[str]:
    """Split a field name across ``_``, ``-`` and camelCase boundaries.

    The previous regex anchored on ``^`` or ``_``, so in a camelCase codebase it matched almost
    nothing — ``privateKey``, ``apiKey`` and ``password`` all passed. Python was safe from that only
    by accident, because ``log(**fields)`` pushes callers to snake_case; the TypeScript side, which
    uses camelCase throughout, was not.
    """
    normalised = _CAMEL_BOUNDARY.sub(r"\1 \2", field)
    return [w.lower() for w in _WORD_SPLIT.split(normalised) if w]


def assert_no_secret(rendered: str) -> None:
    """Refuse rather than redact.

    Redaction lets the call site stay wrong: the developer sees ``[REDACTED]``, shrugs, and ships a
    line that silently discards what they wanted. Raising surfaces the mistake while it is still
    cheap — in a test rather than in a public log.

    A backstop, not the mechanism. The mechanism is fingerprinting where secrets are handled; do not
    read a passing check as proof a line is safe.
    """
    for name, pattern in _SECRET_SHAPES:
        if pattern.search(rendered):
            raise SecretInLogError(name)


def assert_field_name_is_safe(field: str) -> None:
    """A field whose *name* says it carries a secret must carry a fingerprint instead."""
    if field.endswith("_fp"):
        return
    if any(word in _SUSPICIOUS_WORDS for word in _words(field)):
        raise SecretInLogError(f"field named `{field}`")


def assert_fingerprint_shaped(field: str, value: object) -> None:
    """A ``_fp`` field must actually carry a fingerprint, not merely be named like one."""
    if not field.endswith("_fp"):
        return
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value):
        raise SecretInLogError(
            f"field `{field}` claims to be a fingerprint but is not 16 lower-case hex characters"
        )


def log(event: str, **fields: str | int | float | bool | None) -> None:
    """Structured log line, checked before it is emitted.

    Assume every line is public. It very likely is.
    """
    for field, value in fields.items():
        assert_field_name_is_safe(field)
        assert_fingerprint_shaped(field, value)

    # `allow_nan=False` because the default emits bare `NaN`/`Infinity`, which is not JSON and
    # breaks the OTel/Loki pipeline this project standardises on. `ensure_ascii=False` because
    # TypeScript emits raw UTF-8, and identical events must not render as different lines.
    # Large integers are stringified: a uint256 emitted as a bare number is silently rounded to a
    # float by every JavaScript consumer.
    safe = {
        k: (str(v) if isinstance(v, int) and not isinstance(v, bool) and abs(v) > 2**53 else v)
        for k, v in fields.items()
    }
    line = json.dumps({**safe, "event": event}, allow_nan=False, ensure_ascii=False)
    assert_no_secret(line)
    print(line)
