"""Signature verification, mirroring ``ts/test/`` case for case.

This module was at **0% coverage** while its TypeScript counterpart was at 100% — so the
account-type dispatch, the smart-account refusal and the signer-mismatch path were verified in one
language and unverified in the other.

The shared vectors could not have caught that. They pin EIP-712 digests, fingerprints, the seal
bundle and token ids: values, not behaviour. Two implementations can agree on every digest and
still disagree on what they *do* with a signature, and this is the module where that difference
would matter most.
"""

from __future__ import annotations

from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from verity_app.authorization import (
    EXPORT_AUTHORIZATION_FIELDS,
    MIGRATION_AUTHORIZATION_FIELDS,
    ExportAuthorization,
    MigrationAuthorization,
    domain,
)
from verity_app.signature import (
    SignerMismatchError,
    SmartAccountNotSupportedError,
    is_contract_account,
    verify_export_signature,
    verify_migration_signature,
)

CHAIN_ID = 84532
LICENSE_TOKEN = "0x1111111111111111111111111111111111111111"

HOLDER = Account.from_key("0x" + "11" * 32)
STRANGER = Account.from_key("0x" + "22" * 32)

_EIP712_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


class FakeWeb3:
    """Answers ``get_code`` only — the one chain fact this module consults."""

    def __init__(self, code: bytes = b"") -> None:
        self.eth = _FakeEth(code)


class _FakeEth:
    def __init__(self, code: bytes) -> None:
        self._code = code

    def get_code(self, _address: str) -> bytes:
        return self._code


def _migration(**overrides: Any) -> MigrationAuthorization:
    base: dict[str, Any] = {
        "license_id": 42,
        "from_digest": "0x" + "ab" * 32,
        "to_digest": "0x" + "cd" * 32,
        "instance_id": "0x" + "00" * 31 + "ff",
        "nonce": 7,
        "expiry": 4_000_000_000,
    }
    base.update(overrides)
    return MigrationAuthorization(**base)


def _export(**overrides: Any) -> ExportAuthorization:
    base: dict[str, Any] = {
        "license_id": 42,
        "instance_id": "0x" + "00" * 31 + "ff",
        "recipient_public_key": "0x" + "ee" * 32,
        "nonce": 7,
        "expiry": 4_000_000_000,
    }
    base.update(overrides)
    return ExportAuthorization(**base)


def _sign(
    account: Any, primary_type: str, fields: list[dict[str, str]], message: dict[str, Any]
) -> str:
    signable = encode_typed_data(
        full_message={
            "types": {"EIP712Domain": _EIP712_DOMAIN_FIELDS, primary_type: fields},
            "primaryType": primary_type,
            "domain": domain(CHAIN_ID, LICENSE_TOKEN),
            "message": message,
        }
    )
    return account.sign_message(signable).signature.to_0x_hex()


# — the happy path —


def test_a_genuine_migration_signature_verifies() -> None:
    auth = _migration()
    signature = _sign(
        HOLDER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    verify_migration_signature(FakeWeb3(), HOLDER.address, auth, CHAIN_ID, LICENSE_TOKEN, signature)


def test_a_genuine_export_signature_verifies() -> None:
    auth = _export()
    signature = _sign(HOLDER, "ExportAuthorization", EXPORT_AUTHORIZATION_FIELDS, auth.as_message())
    verify_export_signature(FakeWeb3(), HOLDER.address, auth, CHAIN_ID, LICENSE_TOKEN, signature)


# — the two operations are not interchangeable —


def test_a_migration_signature_does_not_authorize_an_export() -> None:
    """Two operations, two types. If a signature for one authorized the other, every check in the
    stricter one would be reachable around — which is exactly how ``LicenseToken.mint`` and
    ``upgrade`` came to share a struct."""
    auth = _export()
    # Same field values, signed under the *migration* type.
    migration_shaped = _sign(
        HOLDER,
        "MigrationAuthorization",
        MIGRATION_AUTHORIZATION_FIELDS,
        _migration(
            license_id=auth.license_id,
            from_digest=auth.recipient_public_key,
            to_digest=auth.recipient_public_key,
            instance_id=auth.instance_id,
            nonce=auth.nonce,
            expiry=auth.expiry,
        ).as_message(),
    )
    with pytest.raises(SignerMismatchError):
        verify_export_signature(
            FakeWeb3(), HOLDER.address, auth, CHAIN_ID, LICENSE_TOKEN, migration_shaped
        )


# — refusals —


def test_a_signature_from_someone_else_is_refused() -> None:
    auth = _migration()
    signature = _sign(
        STRANGER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    with pytest.raises(SignerMismatchError):
        verify_migration_signature(
            FakeWeb3(), HOLDER.address, auth, CHAIN_ID, LICENSE_TOKEN, signature
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("license_id", 43),
        ("from_digest", "0x" + "ee" * 32),
        ("to_digest", "0x" + "ee" * 32),
        ("instance_id", "0x" + "11" * 32),
        ("nonce", 8),
        ("expiry", 4_000_000_001),
    ],
)
def test_tampering_with_any_signed_field_breaks_the_signature(field: str, value: Any) -> None:
    """Every field is in the signature, so altering any of them invalidates it. Each one closes a
    way an authorization could be reused for something the holder did not authorize."""
    auth = _migration()
    signature = _sign(
        HOLDER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    with pytest.raises(SignerMismatchError):
        verify_migration_signature(
            FakeWeb3(),
            HOLDER.address,
            _migration(**{field: value}),
            CHAIN_ID,
            LICENSE_TOKEN,
            signature,
        )


def test_a_different_chain_id_breaks_the_signature() -> None:
    """The EIP-712 domain binds the chain, so a testnet signature cannot verify against mainnet."""
    auth = _migration()
    signature = _sign(
        HOLDER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    with pytest.raises(SignerMismatchError):
        verify_migration_signature(
            FakeWeb3(), HOLDER.address, auth, CHAIN_ID + 1, LICENSE_TOKEN, signature
        )


def test_a_different_verifying_contract_breaks_the_signature() -> None:
    auth = _migration()
    signature = _sign(
        HOLDER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    with pytest.raises(SignerMismatchError):
        verify_migration_signature(
            FakeWeb3(),
            HOLDER.address,
            auth,
            CHAIN_ID,
            "0x2222222222222222222222222222222222222222",
            signature,
        )


# — the dispatch ADR 0005 requires —


def test_a_contract_signer_is_refused_as_unsupported_not_as_a_bad_signature() -> None:
    """ "Not supported yet" and "your signature is wrong" are different problems, and only one of
    them is the caller's. An absent branch is also indistinguishable from an unconsidered one."""
    auth = _migration()
    signature = _sign(
        HOLDER, "MigrationAuthorization", MIGRATION_AUTHORIZATION_FIELDS, auth.as_message()
    )
    with pytest.raises(SmartAccountNotSupportedError):
        verify_migration_signature(
            FakeWeb3(code=b"\x60\x00"), HOLDER.address, auth, CHAIN_ID, LICENSE_TOKEN, signature
        )


def test_the_dispatch_runs_before_recovery() -> None:
    """Recovery against a contract account does not fail loudly — it returns *some* address, which
    is then compared and found unequal, producing "invalid signature" for what is actually an
    unsupported account type. So the dispatch must come first, and a garbage signature on a
    contract account must still say "not supported"."""
    with pytest.raises(SmartAccountNotSupportedError):
        verify_migration_signature(
            FakeWeb3(code=b"\x60\x00"),
            HOLDER.address,
            _migration(),
            CHAIN_ID,
            LICENSE_TOKEN,
            "0x" + "00" * 65,
        )


def test_the_export_path_dispatches_too() -> None:
    with pytest.raises(SmartAccountNotSupportedError):
        verify_export_signature(
            FakeWeb3(code=b"\x60\x00"),
            HOLDER.address,
            _export(),
            CHAIN_ID,
            LICENSE_TOKEN,
            "0x" + "00" * 65,
        )


def test_is_contract_account_distinguishes_by_code() -> None:
    assert is_contract_account(FakeWeb3(code=b"\x60\x00"), HOLDER.address) is True
    assert is_contract_account(FakeWeb3(code=b""), HOLDER.address) is False


# — malformed input —


@pytest.mark.parametrize("signature", ["0x", "0x00", "0x" + "11" * 64])
def test_a_malformed_signature_is_refused_rather_than_recovering_garbage(signature: str) -> None:
    with pytest.raises(Exception):
        verify_migration_signature(
            FakeWeb3(), HOLDER.address, _migration(), CHAIN_ID, LICENSE_TOKEN, signature
        )
