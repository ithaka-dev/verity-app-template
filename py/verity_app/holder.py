"""Who currently holds the licence — resolved from chain state, every time.

Mirrors ``ts/src/holder.ts``.

The mistake this module exists to prevent
-----------------------------------------
The instinct is to record the owner at deploy time and compare against that, calling the chain only
"if needed." **That is wrong, and invisible until someone is harmed by it.**

Spec §2.6 makes licences transferable on purpose: transfer the token, transfer the living instance.
So a baked-in owner means the **previous** holder can still sign valid migrations after selling —
and the new holder's instance obeys them. Every check passes. The signature is genuine. The person
authorizing the mutation sold the thing weeks ago.

Ownership is chain state. Chain state is the only place to read it.

Why ``balanceOf`` and not ``ownerOf``
-------------------------------------
Licences are ERC-1155, which has no ``ownerOf``: several accounts can hold the same ``tokenId``, and
under §2.9 each unit is a runnable instance. The question is not "who is the owner" but "does this
signer hold this licence *now*", which is what actually authorizes the act.
"""

from __future__ import annotations

from typing import Any, Final

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

LICENSE_TOKEN_ABI: Final[list[dict[str, Any]]] = [
    {
        "type": "function",
        "name": "balanceOf",
        "stateMutability": "view",
        "inputs": [
            {"name": "account", "type": "address"},
            {"name": "id", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "instanceOf",
        "stateMutability": "view",
        "inputs": [{"name": "licenseId", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
]


class InstanceNotBoundError(Exception):
    """The licence is not bound to any instance, so it cannot say which one is its own."""

    def __init__(self, license_id: int) -> None:
        super().__init__(
            f"licence {license_id} is not bound to an instance. The holder binds it themselves "
            "with `LicenseToken.bindInstance(licenseId, instanceId)` — until they do, this app "
            "cannot tell whose instance it is and refuses everything."
        )
        self.license_id = license_id


class WrongInstanceLicenseError(Exception):
    """The licence runs a different instance than this one."""

    def __init__(self, bound_instance: str, this_instance: str) -> None:
        super().__init__(
            f"that licence runs instance {bound_instance}, and this is {this_instance}. Holding a "
            "licence for this app is not the same as holding the one this instance runs under."
        )
        self.bound_instance = bound_instance
        self.this_instance = this_instance


class NotCurrentHolderError(Exception):
    def __init__(self, signer: str, token_id: int) -> None:
        super().__init__(
            f"{signer} holds none of licence {token_id}. Licences transfer (spec §2.6), so this "
            "may be a previous holder acting after a sale — which is exactly what resolving from "
            "chain state prevents."
        )
        self.signer = signer
        self.token_id = token_id


def version_id_for(app_manifest: str, version: str) -> int:
    """The identifier of a *version* of an app. Groups licences; **is not one**.

    Nothing is ever minted against it and a balance of it means nothing — that is the whole of
    ADR 0023. Use it to ask "which version is this licence for", never "does this address own this
    instance". Mirrors ``LicenseToken.versionIdFor`` exactly:
    ``keccak256(abi.encode(manifest, keccak256(bytes(version))))``.

    ``abi.encode``, never ``encodePacked``. Packed encoding is injective here — a fixed-width
    address
    prefix cannot be re-split — but it stops being so the moment a second variable-width field is
    added, and that edit would look harmless.

    Kept in sync with Solidity and TypeScript by ``test-vectors/token-id.json`` rather than by
    attention. A mismatch does not fail loudly: it produces a ``balanceOf`` lookup against an id
    nobody holds, so the app reports the real holder as unauthorized.
    """
    version_hash = keccak(version.encode())
    encoded = abi_encode(["address", "bytes32"], [to_checksum_address(app_manifest), version_hash])
    return int.from_bytes(keccak(encoded), "big")


def assert_holds_license(web3: Any, license_token: str, signer: str, license_id: int) -> None:
    """Assert ``signer`` currently holds **this specific licence**.

    An earlier version checked a *version*-derived id. Licences were fungible per version, so that
    established only that the signer was a customer of this app version — and any customer could
    then act on any other customer's instance. Licences are per-unit now (ADR 0023), so the balance
    is 1 or 0 and the question is ownership.

    ``license_id`` must come from the signed authorization, never be derived from a version. The
    caller must separately check it is the licence *this instance* serves.

    :raises NotCurrentHolderError: when the signer does not hold that licence
    """
    contract = web3.eth.contract(address=to_checksum_address(license_token), abi=LICENSE_TOKEN_ABI)
    balance: int = contract.functions.balanceOf(to_checksum_address(signer), license_id).call()
    if balance == 0:
        raise NotCurrentHolderError(signer, license_id)


_UNBOUND = "0x" + "00" * 32


def assert_license_runs_this_instance(
    web3: Any, license_token: str, license_id: int, instance_id: str
) -> None:
    """Assert that ``license_id`` is bound, on chain, to **this** instance.

    Read from chain rather than from the volume (ADR 0024). The volume version was set by the first
    authorization an instance accepted, which worked and had a race nobody could see: whoever
    reached a fresh instance first owned it, silently and permanently, with no record to check.

    On chain the binding is the holder's own transaction, an instance can be claimed by only one
    licence ever, and the holder can verify it before trusting the instance.

    **Both checks are required.** ``assert_holds_license`` says the signer owns the licence; this
    says the licence owns this instance. The first without the second lets any holder of the version
    act on any instance of it; the second without the first lets a stranger act on a bound one.

    :raises InstanceNotBoundError: the holder has not bound the licence yet
    :raises WrongInstanceLicenseError: the licence runs a different instance
    """
    contract = web3.eth.contract(address=to_checksum_address(license_token), abi=LICENSE_TOKEN_ABI)
    bound: bytes = contract.functions.instanceOf(license_id).call()
    bound_hex = "0x" + (bound.hex() if isinstance(bound, bytes) else str(bound).removeprefix("0x"))

    if bound_hex.lower() == _UNBOUND:
        raise InstanceNotBoundError(license_id)
    if bound_hex.lower() != instance_id.lower():
        raise WrongInstanceLicenseError(bound_hex, instance_id)
