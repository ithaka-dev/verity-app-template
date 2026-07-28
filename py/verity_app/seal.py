"""Sealing an export bundle to a key only the holder holds.

Mirrors ``ts/src/seal.ts`` **byte for byte**: a bundle sealed by the TypeScript implementation opens
here and vice versa, which ``tests/test_parity.py`` proves against a fixture. That matters because a
holder's recovery tool will be written in whichever language its author prefers, and an export that
cannot be opened is worse than no export — it is discovered when the data is needed.

Why the encryption happens here rather than at the edge
-------------------------------------------------------
Invariant I7, as amended by ADR 0010: *no plaintext state leaves the CVM except to the holder, under
explicit holder authorization, encrypted in transit to a key only they hold.*

So the bundle is sealed **inside the enclave**. Encrypting at the transport layer instead would mean
plaintext crossing the boundary and being re-protected outside it, which is exactly the exposure I7
exists to prevent — the orchestrator, the host, and anyone who can read a response body would see
it.

The construction
----------------
X25519 ECDH to an ephemeral key, HKDF-SHA256 to derive, AES-256-GCM to encrypt.

**Ephemeral sender key, every time.** The enclave's own derived key is never used. If it were, one
compromise would retroactively open every bundle ever exported; with an ephemeral key the private
half is discarded when the call returns and forward secrecy is free.

The HKDF ``info`` binds the licence and instance, so a bundle cannot be presented as an export of a
different instance — the recipient's own decryption fails if the context does not match.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BUNDLE_VERSION: Final = "verity-export-v1"


class SealError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SealContext:
    """Bound into the derived key, so a bundle cannot be passed off as a different export."""

    license_id: int
    instance_id: str


@dataclass(frozen=True, slots=True)
class SealedBundle:
    version: str
    ephemeral_public_key: str
    iv: str
    ciphertext: str
    tag: str

    def to_dict(self) -> dict[str, str]:
        return {
            "version": self.version,
            "ephemeralPublicKey": self.ephemeral_public_key,
            "iv": self.iv,
            "ciphertext": self.ciphertext,
            "tag": self.tag,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SealedBundle:
        return SealedBundle(
            version=str(data["version"]),
            ephemeral_public_key=str(data["ephemeralPublicKey"]),
            iv=str(data["iv"]),
            ciphertext=str(data["ciphertext"]),
            tag=str(data["tag"]),
        )


def _context_info(context: SealContext) -> bytes:
    return (
        f"{BUNDLE_VERSION}|license={context.license_id}|instance={context.instance_id.lower()}"
    ).encode()


def parse_recipient_key(hex_key: str) -> X25519PublicKey:
    """Parse a holder-supplied X25519 public key: raw 32 bytes of hex, with or without ``0x``.

    Refuses anything else rather than guessing at a format — a misparsed key encrypts to something
    the holder cannot open, and they find out when they need the data.
    """
    raw = hex_key.strip().removeprefix("0x")
    if len(raw) != 64:
        raise SealError(
            f"recipient public key must be 32 bytes of hex (X25519), got {len(raw)} characters"
        )
    try:
        return X25519PublicKey.from_public_bytes(bytes.fromhex(raw))
    except ValueError as err:
        raise SealError(f"recipient public key is not a valid X25519 key: {err}") from err


def _derive_key(shared: bytes, salt: bytes, context: SealContext) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=_context_info(context)
    ).derive(shared)


def seal(plaintext: bytes, recipient: X25519PublicKey, context: SealContext) -> SealedBundle:
    """Seal ``plaintext`` to ``recipient``. The ephemeral private key never leaves this function."""
    import os

    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient)

    # The IV doubles as HKDF salt: already unique per call, already travels with the bundle, so a
    # second random value would add a field without adding entropy.
    iv = os.urandom(12)
    key = _derive_key(shared, iv, context)

    sealed = AESGCM(key).encrypt(iv, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]

    return SealedBundle(
        version=BUNDLE_VERSION,
        ephemeral_public_key=ephemeral.public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
        .hex(),
        iv=iv.hex(),
        ciphertext=base64.b64encode(ciphertext).decode(),
        tag=tag.hex(),
    )


def open_bundle(
    bundle: SealedBundle, recipient_private_key: X25519PrivateKey, context: SealContext
) -> bytes:
    """Open a bundle with the holder's private key.

    Not used by the app — the app never decrypts an export. It exists so the tests can prove the
    holder can actually open what was sealed, and so a holder-side tool has a reference to match.
    """
    if bundle.version != BUNDLE_VERSION:
        raise SealError(f"unsupported bundle version {bundle.version}")

    ephemeral_public = X25519PublicKey.from_public_bytes(bytes.fromhex(bundle.ephemeral_public_key))
    shared = recipient_private_key.exchange(ephemeral_public)

    iv = bytes.fromhex(bundle.iv)
    key = _derive_key(shared, iv, context)

    payload = base64.b64decode(bundle.ciphertext) + bytes.fromhex(bundle.tag)
    try:
        return AESGCM(key).decrypt(iv, payload, None)
    except InvalidTag as err:
        # GCM authentication covers tampering *and* a mismatched context, since the context is in
        # the
        # derived key. Both mean "this is not a bundle you can trust", so they report the same way.
        raise SealError(
            "bundle failed authentication: wrong key, wrong context, or tampered"
        ) from err


def generate_recipient_keypair() -> tuple[str, X25519PrivateKey]:
    """Convenience for tests and holder-side tooling: a fresh X25519 keypair."""
    private = X25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return public_hex, private
