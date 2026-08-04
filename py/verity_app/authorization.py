"""The holder's authorizations, as EIP-712 typed structs.

Mirrors ``ts/src/authorization.ts``. The digests are pinned by ``test-vectors/parity.json``: a
signature is verified against them, so an implementation computing a different digest silently
rejects every genuine holder signature — and does so three layers from the cause.

Why the holder signs at all
---------------------------
The orchestrator asks this app to migrate. The app must not simply believe it. Spec §2.8's direction
is that the orchestrator becomes untrusted — permissionless workers gated by attestation — and an
app that migrates because a box told it to has made that box trusted again at exactly the moment it
is mutating the holder's data. The orchestrator is a *carrier* of a holder-signed fact, never its
author. That is invariant I3 applied one layer in.

Why a mint is not this signature
--------------------------------
Minting says "I want this version." This says "move *this instance's* data from A to B." A holder
may legitimately want the new version without their running instance being touched. **Never migrate
because you observed a mint** (I10) — an implementation can honour ADR 0003 to the letter and still
move someone's data unasked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from eth_account.messages import encode_typed_data
from eth_utils import keccak

DOMAIN_NAME: Final = "Verity App Lifecycle"
DOMAIN_VERSION: Final = "1"

_EIP712_DOMAIN_FIELDS: Final = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

MIGRATION_AUTHORIZATION_FIELDS: Final = [
    {"name": "licenseId", "type": "uint256"},
    {"name": "fromDigest", "type": "bytes32"},
    {"name": "toDigest", "type": "bytes32"},
    {"name": "instanceId", "type": "bytes32"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiry", "type": "uint256"},
]

# Deliberately a **different struct** from the migration one — the two must not be interchangeable.
# That lesson was learned expensively one repo over: ``LicenseToken.mint`` and ``upgrade`` shared a
# signed struct, which made every check in ``upgrade`` decorative because an authorization for one
# could be spent on the other. Two operations, two types, two typehashes.
#
# ``recipientPublicKey`` is signed because it decides *who can read the result*. Left out, a relayer
# could substitute their own key and receive a bundle the holder genuinely authorized.
EXPORT_AUTHORIZATION_FIELDS: Final = [
    {"name": "licenseId", "type": "uint256"},
    {"name": "instanceId", "type": "bytes32"},
    {"name": "recipientPublicKey", "type": "bytes32"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiry", "type": "uint256"},
]


@dataclass(frozen=True, slots=True)
class MigrationAuthorization:
    """Every field closes a way a signature could be reused for something unauthorized.

    ``from_digest`` — without it a signature is reusable against a different instance the same
    holder
    owns. ``instance_id`` — ``from_digest`` alone is not enough, since a holder running two
    instances
    of the same version has two things matching it. ``nonce`` — replay. ``expiry`` — bounds how long
    a leaked signature is useful.
    """

    license_id: int
    from_digest: str
    to_digest: str
    instance_id: str
    nonce: int
    expiry: int

    def as_message(self) -> dict[str, Any]:
        return {
            "licenseId": self.license_id,
            "fromDigest": _to_bytes32(self.from_digest),
            "toDigest": _to_bytes32(self.to_digest),
            "instanceId": _to_bytes32(self.instance_id),
            "nonce": self.nonce,
            "expiry": self.expiry,
        }


@dataclass(frozen=True, slots=True)
class ExportAuthorization:
    license_id: int
    instance_id: str
    recipient_public_key: str
    nonce: int
    expiry: int

    def as_message(self) -> dict[str, Any]:
        return {
            "licenseId": self.license_id,
            "instanceId": _to_bytes32(self.instance_id),
            "recipientPublicKey": _to_bytes32(self.recipient_public_key),
            "nonce": self.nonce,
            "expiry": self.expiry,
        }


class AuthorizationExpiredError(Exception):
    def __init__(self, expiry: int, now: int) -> None:
        super().__init__(f"migration authorization expired at {expiry} (now {now})")
        self.expiry = expiry
        self.now = now


MAX_AUTHORIZATION_LIFETIME_SECONDS = 3600
"""The longest an authorization may claim to be valid for.

A signature is a bearer capability for as long as it is valid, and the party holding it is the
orchestrator — the component spec §2.8 says must become untrusted. An unbounded expiry turns one
holder act into a standing permission, so the app refuses to honour one however genuinely it was
signed. The holder cannot grant more than this by choosing a larger number.

**This was missing here while TypeScript enforced it**, found by T-07's behavioural parity table.
The value vectors could not see it: both languages computed identical EIP-712 digests for an
authorization expiring in the year 2100, agreed on every byte, and then one honoured it and the
other refused. Parity of values is not parity of behaviour.
"""


class AuthorizationLifetimeTooLongError(Exception):
    """The authorization claims a validity window longer than the app will honour."""

    def __init__(self, expiry: int, maximum: int) -> None:
        super().__init__(
            f"authorization is valid until {expiry}, more than {maximum}s ahead; refusing to "
            "honour a window this long — see MAX_AUTHORIZATION_LIFETIME_SECONDS"
        )
        self.expiry = expiry
        self.maximum = maximum


def _assert_lifetime_is_bounded(expiry: int, now: int) -> None:
    if expiry > now + MAX_AUTHORIZATION_LIFETIME_SECONDS:
        raise AuthorizationLifetimeTooLongError(expiry, MAX_AUTHORIZATION_LIFETIME_SECONDS)


class AuthorizationMismatchError(Exception):
    def __init__(self, field: str, expected: str, actual: str) -> None:
        super().__init__(
            f"migration authorization {field} mismatch: expected {expected}, got {actual}"
        )
        self.field = field
        self.expected = expected
        self.actual = actual


def _to_bytes32(value: str) -> bytes:
    """Parse a canonical 32-byte hex value.

    **Exactly 32 bytes, never padded.** An earlier version left-padded, which made ``0xcd`` and
    ``0x00...cd`` the same value in Python and two different ones in TypeScript — viem rejects the
    short form outright. Two encodings of "the same" authorization producing two different EIP-712
    digests is a signature that verifies in one language and not the other.
    """
    raw = value[2:] if value.startswith("0x") else value
    if len(raw) != 64:
        raise ValueError(
            f"expected a 32-byte hex value, got {len(raw)} hex characters ({value!r}). "
            "Canonicalise at the boundary with `pad_to_bytes32`, not here."
        )
    try:
        return bytes.fromhex(raw)
    except ValueError as err:
        raise ValueError(f"{value!r} is not hexadecimal") from err


def pad_to_bytes32(value: str) -> str:
    """Canonicalise a platform-supplied identifier into the form the holder signs.

    Mirrors ``toBytes32`` in ``ts/src/handlers/migrate.ts``: a **boundary** normaliser for
    guest-agent output, never applied to a signed struct. dStack reports ``instance_id`` as bare
    20-byte hex, and the value in the authorization is the padded ``bytes32``.
    """
    raw = value[2:] if value.startswith("0x") else value
    if len(raw) > 64:
        raise ValueError(f"{value!r} does not fit in bytes32")
    if raw and not all(c in "0123456789abcdefABCDEF" for c in raw):
        raise ValueError(f"{value!r} is not hexadecimal")
    return "0x" + raw.rjust(64, "0").lower()


def domain(chain_id: int, license_token: str) -> dict[str, Any]:
    """The EIP-712 domain.

    ``chainId`` prevents cross-chain replay. ``verifyingContract`` is the ``LicenseToken`` this
    app's
    licences live in, which separates deployments — a signature for a testnet licence must not
    verify
    against a mainnet one, and under ADR 0002 everything is testnet, so that separation is doing
    real
    work now rather than someday.
    """
    return {
        "name": DOMAIN_NAME,
        "version": DOMAIN_VERSION,
        "chainId": chain_id,
        "verifyingContract": license_token,
    }


def _hash_typed(
    primary_type: str,
    fields: list[dict[str, str]],
    message: dict[str, Any],
    chain_id: int,
    license_token: str,
) -> bytes:
    signable = encode_typed_data(
        full_message={
            "types": {"EIP712Domain": _EIP712_DOMAIN_FIELDS, primary_type: fields},
            "primaryType": primary_type,
            "domain": domain(chain_id, license_token),
            "message": message,
        }
    )
    # `signable.body` is the struct hash and `signable.header` the domain separator; the digest is
    # keccak over the 0x1901 prefix and both, which is what a wallet signs.
    digest: bytes = keccak(b"\x19\x01" + signable.header + signable.body)
    return digest


def hash_migration_authorization(
    authorization: MigrationAuthorization, chain_id: int, license_token: str
) -> str:
    """The digest a holder signs to authorize a migration."""
    digest = _hash_typed(
        "MigrationAuthorization",
        MIGRATION_AUTHORIZATION_FIELDS,
        authorization.as_message(),
        chain_id,
        license_token,
    )
    return "0x" + digest.hex()


def hash_export_authorization(
    authorization: ExportAuthorization, chain_id: int, license_token: str
) -> str:
    """The digest a holder signs to authorize an export."""
    digest = _hash_typed(
        "ExportAuthorization",
        EXPORT_AUTHORIZATION_FIELDS,
        authorization.as_message(),
        chain_id,
        license_token,
    )
    return "0x" + digest.hex()


@dataclass(frozen=True, slots=True)
class ExpectedContext:
    """What the app independently knows about its own situation.

    **Every field here must come from somewhere other than the authorization.** Comparing an
    authorization's field against itself type-checks, reads like a check, and verifies nothing — and
    it is the natural shape to write by accident, because both values are right there. That mistake
    was made and caught in the TypeScript implementation before it shipped.
    """

    running_compose_hash: str
    previous_compose_hash: str | None
    instance_id: str


def assert_authorization_matches(
    authorization: MigrationAuthorization, expected: ExpectedContext, now: int
) -> None:
    """Check the authorization describes *this* migration, on *this* instance, right now.

    Signature validity is a separate question. Both must hold: a genuine signature over the wrong
    instance is exactly the attack ``instance_id`` exists to stop, and a signature check alone would
    accept it.
    """
    if now > authorization.expiry:
        raise AuthorizationExpiredError(authorization.expiry, now)
    _assert_lifetime_is_bounded(authorization.expiry, now)
    _assert_equal("toDigest", expected.running_compose_hash, authorization.to_digest)
    _assert_equal("instanceId", expected.instance_id, authorization.instance_id)
    if expected.previous_compose_hash is not None:
        _assert_equal("fromDigest", expected.previous_compose_hash, authorization.from_digest)


def assert_export_authorization_matches(
    authorization: ExportAuthorization, expected_instance_id: str, now: int
) -> None:
    if now > authorization.expiry:
        raise AuthorizationExpiredError(authorization.expiry, now)
    _assert_lifetime_is_bounded(authorization.expiry, now)
    _assert_equal("instanceId", expected_instance_id, authorization.instance_id)


def _assert_equal(field: str, expected: str, actual: str) -> None:
    """Compare canonical hex strings, case-insensitively — and refuse an empty expected value.

    An earlier version normalised **both** sides through a padding parser, which turned a missing
    platform value into a pass: with ``expected == ""`` and an authorization naming ``0x00...00``,
    the check succeeded. TypeScript rejects that, and its ``migrate`` handler has a second guard
    naming the failure — *"the check would degrade to 'the message agrees with itself', which
    passes for any authorization at all."* Python had neither, and documented the normalisation as
    deliberate, which guaranteed no reviewer would question it.
    """
    if not expected:
        raise AuthorizationMismatchError(field, "<missing>", actual)
    if expected.strip().lower() != actual.strip().lower():
        raise AuthorizationMismatchError(field, expected, actual)
