"""Signature verification that dispatches on account type.

Mirrors ``ts/src/signature.ts``.

Read this before changing anything here
---------------------------------------
``ecrecover`` recovers an ECDSA signer and works **only for an EOA**. The moment a holder's account
is an ERC-4337 smart account there is no key to recover, and verification silently has no valid
path. That is not speculative — it is precisely the failure already documented for x402's
recommended EIP-3009 payment method, which turned out to be EOA-only.

ADR 0002 defers account abstraction, so the EOA branch is sufficient for MVP. But that same ADR
makes AA a **hard gate on any real-value deployment**, which means every app written against bare
``ecrecover`` breaks at that gate — and apps built from this template are third-party software
nobody can patch.

**So the dispatch exists from the first published version, even though one branch raises.** The
shape is the deliverable. Filling in ERC-1271 later is adding a case to a function; retrofitting
this structure into a hundred cloned apps is not possible at all.

Why the smart-account branch raises rather than returning False
---------------------------------------------------------------
"Not supported yet" and "your signature is wrong" are different problems and only one of them is the
caller's. An absent branch is also indistinguishable from an unconsidered one.
"""

from __future__ import annotations

from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

from .authorization import (
    EXPORT_AUTHORIZATION_FIELDS,
    MIGRATION_AUTHORIZATION_FIELDS,
    ExportAuthorization,
    MigrationAuthorization,
    domain,
)

_EIP712_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


class SmartAccountNotSupportedError(Exception):
    def __init__(self, account: str) -> None:
        super().__init__(
            f"{account} is a contract account. ERC-1271 verification is not implemented in MVP "
            "(ADR 0002 defers account abstraction). This is a known gap, not a signature failure."
        )
        self.account = account


class SignerMismatchError(Exception):
    def __init__(self, expected: str, recovered: str) -> None:
        super().__init__(f"signature recovers to {recovered}, expected {expected}")
        self.expected = expected
        self.recovered = recovered


def is_contract_account(web3: Any, account: str) -> bool:
    """Whether an address currently has contract code deployed at it."""
    code: bytes = web3.eth.get_code(to_checksum_address(account))
    return len(code) > 0


def _verify(
    web3: Any,
    signer: str,
    primary_type: str,
    fields: list[dict[str, str]],
    message: dict[str, Any],
    chain_id: int,
    license_token: str,
    signature: str,
) -> None:
    # Dispatch first, so a contract account never reaches ECDSA recovery. Recovery against a
    # contract
    # account does not fail loudly — it returns *some* address, which is then compared and found
    # unequal, producing "invalid signature" for what is actually an unsupported account type.
    if is_contract_account(web3, signer):
        # ERC-1271 goes here. Deliberately not enabled: the rest of the system refuses smart
        # accounts
        # too (see SignatureChecker.sol), and an app accepting one while LicenseToken could not mint
        # to it would produce a half-working story worse than a clear refusal. Enable both together.
        raise SmartAccountNotSupportedError(signer)

    signable = encode_typed_data(
        full_message={
            "types": {"EIP712Domain": _EIP712_DOMAIN_FIELDS, primary_type: fields},
            "primaryType": primary_type,
            "domain": domain(chain_id, license_token),
            "message": message,
        }
    )
    recovered = Account.recover_message(signable, signature=signature)
    if recovered.lower() != signer.lower():
        raise SignerMismatchError(signer, recovered)


def verify_migration_signature(
    web3: Any,
    signer: str,
    authorization: MigrationAuthorization,
    chain_id: int,
    license_token: str,
    signature: str,
) -> None:
    """Raises on every failure rather than returning a boolean.

    A boolean invites ``if ok:`` with no else, and the else is the branch that matters when the
    action mutates someone's data.
    """
    _verify(
        web3,
        signer,
        "MigrationAuthorization",
        MIGRATION_AUTHORIZATION_FIELDS,
        authorization.as_message(),
        chain_id,
        license_token,
        signature,
    )


def verify_export_signature(
    web3: Any,
    signer: str,
    authorization: ExportAuthorization,
    chain_id: int,
    license_token: str,
    signature: str,
) -> None:
    """Separate from the migration check, and using a different primary type, so a signature for one
    operation cannot be presented for the other."""
    _verify(
        web3,
        signer,
        "ExportAuthorization",
        EXPORT_AUTHORIZATION_FIELDS,
        authorization.as_message(),
        chain_id,
        license_token,
        signature,
    )
