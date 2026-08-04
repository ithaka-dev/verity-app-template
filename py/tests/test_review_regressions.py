"""Regressions from the adversarial review.

Every test here is a defect that shipped. Each names the divergence or the failure it prevents,
because the point of a template is that the next person reads the reasoning rather than
rediscovering it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verity_app.authorization import (
    AuthorizationMismatchError,
    ExpectedContext,
    MigrationAuthorization,
    assert_authorization_matches,
    pad_to_bytes32,
)
from verity_app.logging import SecretInLogError, assert_field_name_is_safe, log
from verity_app.seal import (
    SealContext,
    SealedBundle,
    SealError,
    generate_recipient_keypair,
    open_bundle,
    parse_recipient_key,
    seal,
)
from verity_app.state import (
    JsonStore,
    StoreError,
    VersionedDocument,
    migrate_profiles,
    record_outcome,
    split_name,
)

FULL = "0x" + "ab" * 32
OTHER = "0x" + "cd" * 32


def _auth(**overrides: object) -> MigrationAuthorization:
    base: dict[str, object] = {
        "license_id": 1,
        "from_digest": OTHER,
        "to_digest": FULL,
        "instance_id": "0x" + "11" * 32,
        "nonce": 1,
        # Was 4_000_000_000 — a validity window of roughly 127 years, which every test here ran
        # under without anything objecting. It does now: T-07's parity table found that TypeScript
        # bounded an authorization's lifetime and Python did not, and closing that gap made these
        # fixtures illegal. Both tests below use `now=1`, so this sits inside
        # MAX_AUTHORIZATION_LIFETIME_SECONDS while still being comfortably unexpired.
        "expiry": 3_600,
    }
    base.update(overrides)
    return MigrationAuthorization(**base)  # type: ignore[arg-type]


# — C1: a missing platform value must not pass —


@pytest.mark.parametrize("missing", ["", "0x"])
def test_an_empty_expected_value_is_refused(missing: str) -> None:
    """Both sides used to be normalised through a padding parser, so an empty expected value
    compared equal to an all-zero authorization field. That is the "message agrees with itself"
    failure the TypeScript migrate handler has a second guard against; Python had neither."""
    authorization = _auth(instance_id="0x" + "00" * 32)
    with pytest.raises(AuthorizationMismatchError):
        assert_authorization_matches(
            authorization,
            ExpectedContext(
                running_compose_hash=FULL, previous_compose_hash=None, instance_id=missing
            ),
            now=1,
        )


def test_case_differences_are_not_mismatches() -> None:
    assert_authorization_matches(
        _auth(),
        ExpectedContext(
            running_compose_hash="0x" + "AB" * 32,
            previous_compose_hash=None,
            instance_id="0x" + "11" * 32,
        ),
        now=1,
    )


# — C2: a short hex value is not silently padded into validity —


@pytest.mark.parametrize("bad", ["0xcd", "", "0x", "0x" + "ab" * 31])
def test_short_values_are_refused_not_padded(bad: str) -> None:
    """`0xcd` and `0x00...cd` were one value in Python and two in TypeScript, where viem rejects the
    short form outright. Two encodings producing two digests is a signature that verifies in one
    language and not the other."""
    with pytest.raises(ValueError):
        _auth(to_digest=bad).as_message()


def test_the_boundary_normaliser_is_separate_and_explicit() -> None:
    """Padding is legitimate for platform output — dStack reports a bare 20-byte instance id — but
    it belongs at the boundary, not inside the signed struct."""
    assert pad_to_bytes32("0xff") == "0x" + "00" * 31 + "ff"
    assert pad_to_bytes32("ff") == "0x" + "00" * 31 + "ff"
    with pytest.raises(ValueError):
        pad_to_bytes32("zz")


# — H1: refuse to guess rather than corrupt —


@pytest.mark.parametrize("name", [None, 123, {"a": 1}])
def test_a_non_string_name_is_refused(name: object) -> None:
    """`str(None)` wrote the literal "None" into the holder's record, and the idempotency check then
    locked it in permanently — there is no down migration."""
    with pytest.raises(ValueError):
        split_name({"profiles": [{"id": "a", "name": name}]})


def test_unrecognised_state_is_refused_not_reset(tmp_path: Path) -> None:
    """`{"data": null}` used to be silently rewritten to an empty document — state loss, in the
    module whose docstring is entirely about state loss."""
    store = JsonStore(tmp_path)
    store.write("profiles", VersionedDocument(1, None))
    with pytest.raises(ValueError):
        migrate_profiles(store)


# — H2: bool is not a schema version —


def test_a_boolean_schema_version_is_refused(tmp_path: Path) -> None:
    """`isinstance(True, int)` is True in Python, so migration ran from schema `True`."""
    (tmp_path / "profiles.json").write_text('{"schemaVersion": true, "data": {}}')
    with pytest.raises(StoreError):
        JsonStore(tmp_path).read("profiles")


def test_an_integral_float_schema_version_is_accepted(tmp_path: Path) -> None:
    """TypeScript writes JSON numbers and is the writer this must interoperate with."""
    (tmp_path / "profiles.json").write_text('{"schemaVersion": 2.0, "data": {"profiles": []}}')
    document = JsonStore(tmp_path).read("profiles")
    assert document is not None
    assert document.schema_version == 2


# — H3: a typo must not silently disable the replay guard —


def test_an_unknown_journal_status_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        record_outcome(JsonStore(tmp_path), 1, "completed")


# — H4: the denylist must catch camelCase —


@pytest.mark.parametrize(
    "field",
    [
        "privateKey",
        "derivedKey",
        "apiKey",
        "sessionToken",
        "password",
        "x25519PrivateKey",
        "api-key",
    ],
)
def test_camel_case_secret_names_are_refused(field: str) -> None:
    with pytest.raises(SecretInLogError):
        assert_field_name_is_safe(field)


@pytest.mark.parametrize("field", ["compose_hash", "instanceId", "key_fp", "schemaVersion"])
def test_ordinary_names_still_pass(field: str) -> None:
    assert_field_name_is_safe(field)


def test_a_fingerprint_field_must_carry_a_fingerprint() -> None:
    """The `_fp` escape was granted on the name alone, so `{key_fp: raw_private_key}` passed."""
    with pytest.raises(SecretInLogError):
        log("x", key_fp="a" * 64)


def test_large_integers_are_stringified(capsys: pytest.CaptureFixture[str]) -> None:
    """A uint256 emitted as a bare JSON number is silently rounded to a float by JS consumers."""
    log("mint", nonce=2**200)
    assert json.loads(capsys.readouterr().out)["nonce"] == str(2**200)


def test_non_finite_numbers_are_refused() -> None:
    """`json.dumps` emits bare `NaN` by default, which is not JSON."""
    with pytest.raises(ValueError):
        log("x", ratio=float("inf"))


# — M5/M6: crypto failures surface as SealError —


@pytest.mark.parametrize("point", ["00" * 32, "01" + "00" * 31, "ee" + "ff" * 30 + "7f"])
def test_small_order_recipient_keys_are_refused(point: str) -> None:
    """These parse cleanly and then fail inside `exchange()` with a raw OpenSSL string that reaches
    the holder through `export failed: ...`."""
    with pytest.raises(SealError):
        parse_recipient_key(point)


def test_a_malformed_bundle_raises_seal_error() -> None:
    public_hex, private_key = generate_recipient_keypair()
    context = SealContext(license_id=1, instance_id="0x01")
    good = seal(b"x", parse_recipient_key(public_hex), context).to_dict()

    for broken in (
        {**good, "ephemeralPublicKey": "zz"},
        {**good, "iv": "nothex"},
        {**good, "ciphertext": "!!!not base64!!!"},
        {**good, "tag": "qq"},
    ):
        with pytest.raises(SealError):
            open_bundle(SealedBundle.from_dict(broken), private_key, context)


def test_empty_plaintext_round_trips() -> None:
    public_hex, private_key = generate_recipient_keypair()
    context = SealContext(license_id=1, instance_id="0x01")
    bundle = seal(b"", parse_recipient_key(public_hex), context)
    assert open_bundle(bundle, private_key, context) == b""
