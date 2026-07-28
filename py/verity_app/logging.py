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
_SUSPICIOUS_FIELD: Final[re.Pattern[str]] = re.compile(
    r"(?:^|_)(key|secret|private|passphrase|seed|mnemonic|token)(?:$|_)", re.IGNORECASE
)


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
    if _SUSPICIOUS_FIELD.search(field):
        raise SecretInLogError(f"field named `{field}`")


def log(event: str, **fields: str | int | float | bool | None) -> None:
    """Structured log line, checked before it is emitted.

    Assume every line is public. It very likely is.
    """
    for field in fields:
        assert_field_name_is_safe(field)
    line = json.dumps({"event": event, **fields})
    assert_no_secret(line)
    print(line)
