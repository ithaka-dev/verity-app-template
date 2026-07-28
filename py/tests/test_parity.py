"""Parity with the TypeScript implementation.

The two implementations teach the same contract or they teach two. These tests are what make the
first true: every value here was produced by the TypeScript side, and Python must reproduce or
consume it exactly.

None of these failures would be loud in production. A different EIP-712 digest silently rejects
every genuine holder signature. A different ``tokenId`` looks up a balance nobody holds, so the app
reports the real holder as unauthorized. A different seal construction produces a bundle the
holder's tool cannot open, discovered when they need the data. All three surface three layers from
the cause.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from verity_app.authorization import (
    ExportAuthorization,
    MigrationAuthorization,
    hash_export_authorization,
    hash_migration_authorization,
)
from verity_app.holder import version_id_for
from verity_app.logging import fingerprint
from verity_app.seal import SealContext, SealedBundle, open_bundle

VECTORS = json.loads((Path(__file__).parents[2] / "test-vectors" / "parity.json").read_text())
TOKEN_IDS = json.loads((Path(__file__).parents[2] / "test-vectors" / "token-id.json").read_text())


def _domain() -> tuple[int, str]:
    d: dict[str, Any] = VECTORS["eip712"]["domain"]
    return int(d["chainId"]), str(d["verifyingContract"])


def test_migration_digest_matches_typescript() -> None:
    chain_id, license_token = _domain()
    message = VECTORS["eip712"]["migration"]["message"]
    authorization = MigrationAuthorization(
        license_id=int(message["licenseId"]),
        from_digest=message["fromDigest"],
        to_digest=message["toDigest"],
        instance_id=message["instanceId"],
        nonce=int(message["nonce"]),
        expiry=int(message["expiry"]),
    )
    assert (
        hash_migration_authorization(authorization, chain_id, license_token)
        == VECTORS["eip712"]["migration"]["digest"]
    )


def test_export_digest_matches_typescript() -> None:
    chain_id, license_token = _domain()
    message = VECTORS["eip712"]["export"]["message"]
    authorization = ExportAuthorization(
        license_id=int(message["licenseId"]),
        instance_id=message["instanceId"],
        recipient_public_key=message["recipientPublicKey"],
        nonce=int(message["nonce"]),
        expiry=int(message["expiry"]),
    )
    assert (
        hash_export_authorization(authorization, chain_id, license_token)
        == VECTORS["eip712"]["export"]["digest"]
    )


def test_the_two_authorization_digests_differ() -> None:
    """Two operations, two types. If these ever collide, a signature for one authorizes the other —
    which is exactly how ``LicenseToken.mint`` and ``upgrade`` came to share a struct and made every
    check in one of them decorative."""
    assert VECTORS["eip712"]["migration"]["digest"] != VECTORS["eip712"]["export"]["digest"]


@pytest.mark.parametrize("vector", VECTORS["fingerprints"])
def test_fingerprints_match_typescript(vector: dict[str, str]) -> None:
    assert fingerprint(vector["domain"], vector["secret"]) == vector["value"]  # type: ignore[arg-type]


@pytest.mark.parametrize("vector", TOKEN_IDS["vectors"])
def test_version_ids_match_solidity(vector: dict[str, str]) -> None:
    """These came from ``LicenseToken.versionIdFor`` and were asserted against the deployed
    bytecode, so this pins Python to Solidity rather than to TypeScript."""
    assert version_id_for(vector["appManifest"], vector["version"]) == int(vector["tokenId"], 16)


def test_python_opens_a_bundle_sealed_by_typescript() -> None:
    """The strongest of these: a bundle Python did not create, opened with the holder's key.

    Round-tripping within one language proves only that it is self-consistent. This proves the two
    constructions are the *same* construction — same ECDH, same HKDF salt and info, same AEAD
    framing — which is what a holder's recovery tool depends on.
    """
    seal_vector = VECTORS["seal"]
    private_key = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(seal_vector["recipientPrivateKeyHex"])
    )
    context = SealContext(
        license_id=int(seal_vector["context"]["licenseId"]),
        instance_id=seal_vector["context"]["instanceId"],
    )
    plaintext = open_bundle(SealedBundle.from_dict(seal_vector["bundle"]), private_key, context)
    assert plaintext.decode() == seal_vector["plaintext"]


def test_a_bundle_does_not_open_under_a_different_context() -> None:
    """The context is inside the derived key, so a bundle cannot be passed off as another export."""
    from verity_app.seal import SealError

    seal_vector = VECTORS["seal"]
    private_key = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(seal_vector["recipientPrivateKeyHex"])
    )
    wrong = SealContext(
        license_id=int(seal_vector["context"]["licenseId"]) + 1,
        instance_id=seal_vector["context"]["instanceId"],
    )
    with pytest.raises(SealError):
        open_bundle(SealedBundle.from_dict(seal_vector["bundle"]), private_key, wrong)


def test_the_recipient_public_key_derives_from_the_private_one() -> None:
    """Guards the fixture itself: a mismatched pair would make the seal test vacuous rather than
    failing, since it would simply never be exercised as intended."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    seal_vector = VECTORS["seal"]
    private_key = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(seal_vector["recipientPrivateKeyHex"])
    )
    derived = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert derived == seal_vector["recipientPublicKeyHex"]
