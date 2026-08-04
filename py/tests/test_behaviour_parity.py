"""T-07: the Python half of the *behavioural* parity contract.

``parity.json`` pins what the two languages compute. ``behaviour.json`` pins what they decide, and
the gap between those was not hypothetical. Both implementations produced byte-identical EIP-712
digests for an authorization expiring in the year 2100 — agreeing on every digest, fingerprint and
token id in ``parity.json`` — and then TypeScript refused it while **this** implementation honoured
it. No value vector could have caught that, because no value differed.

That missing rule is now :data:`MAX_AUTHORIZATION_LIFETIME_SECONDS`, and the case that found it is
in the table below.

Each case names its expected outcome as a language-neutral reason, which each side maps to its own
exception type. The mapping is the point: it catches a language that refuses for the *wrong* reason,
not only one that fails to refuse. Ordering is behaviour too — checking fields before the clock
reports a stale authorization as a mismatch, which sends whoever reads the log after the wrong bug.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verity_app.authorization import (
    MAX_AUTHORIZATION_LIFETIME_SECONDS,
    AuthorizationExpiredError,
    AuthorizationLifetimeTooLongError,
    AuthorizationMismatchError,
    ExpectedContext,
    ExportAuthorization,
    MigrationAuthorization,
    assert_authorization_matches,
    assert_export_authorization_matches,
)

_BEHAVIOUR = json.loads(
    (Path(__file__).resolve().parents[2] / "test-vectors" / "behaviour.json").read_text()
)


def _reason_for(error: Exception) -> str | None:
    """Translate an exception into the table's language-neutral reason.

    ``None`` for anything unrecognised rather than a catch-all string, so an unexpected exception
    type fails loudly instead of being folded into whatever the case expected.
    """
    if isinstance(error, AuthorizationExpiredError):
        return "AuthorizationExpired"
    if isinstance(error, AuthorizationLifetimeTooLongError):
        return "AuthorizationLifetimeTooLong"
    if isinstance(error, AuthorizationMismatchError):
        return f"AuthorizationMismatch:{error.field}"
    return None


def _check(case: dict[str, Any], run: Any) -> None:
    name = case["name"]
    thrown: Exception | None = None
    try:
        run()
    except Exception as err:  # the point is to see whatever came out, not to filter
        thrown = err

    if case["outcome"] == "accept":
        assert thrown is None, f"{name}: expected acceptance, got {thrown!r}"
        return

    assert thrown is not None, f"{name}: expected refusal ({case['reason']}), got none"
    actual = _reason_for(thrown)
    assert actual is not None, (
        f"{name}: refused with an exception the parity table does not name: {thrown!r}"
    )
    assert actual == case["reason"], f"{name}: refused for the wrong reason"


@pytest.mark.parametrize(
    "case", _BEHAVIOUR["migration"], ids=[c["name"] for c in _BEHAVIOUR["migration"]]
)
def test_migration_behaviour_matches_the_shared_table(case: dict[str, Any]) -> None:
    auth = MigrationAuthorization(
        license_id=case["authorization"]["licenseId"],
        from_digest=case["authorization"]["fromDigest"],
        to_digest=case["authorization"]["toDigest"],
        instance_id=case["authorization"]["instanceId"],
        nonce=case["authorization"]["nonce"],
        expiry=case["authorization"]["expiry"],
    )
    expected = ExpectedContext(
        running_compose_hash=case["expected"]["runningComposeHash"],
        previous_compose_hash=case["expected"]["previousComposeHash"],
        instance_id=case["expected"]["instanceId"],
    )
    _check(case, lambda: assert_authorization_matches(auth, expected, case["now"]))


@pytest.mark.parametrize(
    "case", _BEHAVIOUR["export"], ids=[c["name"] for c in _BEHAVIOUR["export"]]
)
def test_export_behaviour_matches_the_shared_table(case: dict[str, Any]) -> None:
    auth = ExportAuthorization(
        license_id=case["authorization"]["licenseId"],
        instance_id=case["authorization"]["instanceId"],
        recipient_public_key=case["authorization"]["recipientPublicKey"],
        nonce=case["authorization"]["nonce"],
        expiry=case["authorization"]["expiry"],
    )
    _check(
        case,
        lambda: assert_export_authorization_matches(auth, case["expectedInstanceId"], case["now"]),
    )


def test_the_lifetime_constant_matches_the_one_the_table_assumes() -> None:
    """If an implementation changes it, the boundary cases stop testing a boundary and start
    testing an arbitrary interior point — silently, and while still passing."""
    assert (
        _BEHAVIOUR["constants"]["maxAuthorizationLifetimeSeconds"]
        == MAX_AUTHORIZATION_LIFETIME_SECONDS
    )


def test_every_case_in_the_table_was_run() -> None:
    """A table that quietly shrank would keep passing. Both suites assert the count, so deleting an
    inconvenient case has to be done twice and shows up in both diffs."""
    assert len(_BEHAVIOUR["migration"]) == 14
    assert len(_BEHAVIOUR["export"]) == 5
