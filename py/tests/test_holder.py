"""Ownership checks: does this signer hold the licence, and does the licence run this instance.

At 49% coverage, the two functions ADR 0023 and ADR 0024 exist to enforce were untested on the
Python side while the TypeScript side had them covered — including the cross-holder scenario a
review demonstrated end to end.

**Neither check is sufficient alone**, which is the property these tests exist to hold:

- holding a licence without it running this instance lets any customer of the version act on any
  instance of it — the defect ADR 0023 was written for;
- the licence running this instance without the signer holding it lets a stranger act on a bound
  one.
"""

from __future__ import annotations

from typing import Any

import pytest

from verity_app.holder import (
    InstanceNotBoundError,
    NotCurrentHolderError,
    WrongInstanceLicenseError,
    assert_holds_license,
    assert_license_runs_this_instance,
    version_id_for,
)

LICENSE_TOKEN = "0x1111111111111111111111111111111111111111"
MANIFEST = "0x2222222222222222222222222222222222222222"
ALICE = "0x00000000000000000000000000000000000000A1"
MALLORY = "0x00000000000000000000000000000000000000B2"

ALICE_LICENCE = 1111
MALLORY_LICENCE = 2222
INSTANCE = "0x" + "ab" * 32
UNBOUND = "0x" + "00" * 32


class FakeChain:
    """Answers `balanceOf` and `instanceOf` separately.

    A double returning one value for every call could not distinguish "this address holds a licence"
    from "this licence runs this instance" — the entire distinction under test.
    """

    def __init__(
        self,
        balances: dict[tuple[str, int], int] | None = None,
        bindings: dict[int, str] | None = None,
    ) -> None:
        self.eth = _FakeEth(balances or {}, bindings or {})


class _FakeEth:
    def __init__(self, balances: dict[tuple[str, int], int], bindings: dict[int, str]) -> None:
        self._balances = balances
        self._bindings = bindings

    def contract(self, address: str, abi: Any) -> _FakeContract:
        return _FakeContract(self._balances, self._bindings)


class _FakeContract:
    def __init__(self, balances: dict[tuple[str, int], int], bindings: dict[int, str]) -> None:
        self.functions = _FakeFunctions(balances, bindings)


class _FakeFunctions:
    def __init__(self, balances: dict[tuple[str, int], int], bindings: dict[int, str]) -> None:
        self._balances = balances
        self._bindings = bindings

    def balanceOf(self, account: str, token_id: int) -> _Call:  # noqa: N802
        return _Call(self._balances.get((account.lower(), token_id), 0))

    def instanceOf(self, license_id: int) -> _Call:  # noqa: N802
        raw = self._bindings.get(license_id, UNBOUND)
        return _Call(bytes.fromhex(raw.removeprefix("0x")))


class _Call:
    def __init__(self, value: Any) -> None:
        self._value = value

    def call(self) -> Any:
        return self._value


# — ADR 0023: holding a specific licence —


def test_a_holder_of_the_licence_passes() -> None:
    chain = FakeChain(balances={(ALICE.lower(), ALICE_LICENCE): 1})
    assert_holds_license(chain, LICENSE_TOKEN, ALICE, ALICE_LICENCE)


def test_holding_nothing_is_refused() -> None:
    with pytest.raises(NotCurrentHolderError):
        assert_holds_license(FakeChain(), LICENSE_TOKEN, ALICE, ALICE_LICENCE)


def test_holding_a_different_licence_is_refused() -> None:
    """The property per-unit ids exist for. Mallory is a genuine paying customer of the same app —
    she holds her own licence — and that must not admit her to Alice's."""
    chain = FakeChain(balances={(MALLORY.lower(), MALLORY_LICENCE): 1})
    with pytest.raises(NotCurrentHolderError):
        assert_holds_license(chain, LICENSE_TOKEN, MALLORY, ALICE_LICENCE)


def test_a_previous_holder_is_refused_the_moment_their_balance_is_zero() -> None:
    """Licences transfer (§2.6), so this is read fresh on every call rather than cached. A cached
    answer would let a seller keep acting on an instance they sold."""
    sold = FakeChain(balances={(ALICE.lower(), ALICE_LICENCE): 0})
    with pytest.raises(NotCurrentHolderError):
        assert_holds_license(sold, LICENSE_TOKEN, ALICE, ALICE_LICENCE)


def test_the_error_names_the_signer_and_the_licence() -> None:
    with pytest.raises(NotCurrentHolderError) as caught:
        assert_holds_license(FakeChain(), LICENSE_TOKEN, ALICE, ALICE_LICENCE)
    assert caught.value.signer == ALICE
    assert caught.value.token_id == ALICE_LICENCE


# — ADR 0024: the licence runs *this* instance —


def test_a_licence_bound_to_this_instance_passes() -> None:
    chain = FakeChain(bindings={ALICE_LICENCE: INSTANCE})
    assert_license_runs_this_instance(chain, LICENSE_TOKEN, ALICE_LICENCE, INSTANCE)


def test_an_unbound_licence_is_refused_rather_than_assumed() -> None:
    """Zero means unbound. Treating it as a match would make every fresh instance answer to every
    licence."""
    with pytest.raises(InstanceNotBoundError):
        assert_license_runs_this_instance(FakeChain(), LICENSE_TOKEN, ALICE_LICENCE, INSTANCE)


def test_a_licence_bound_elsewhere_is_refused() -> None:
    """**The cross-holder attack, on the Python side.** Mallory holds her own licence for this app
    and names this instance. Her licence runs a different one, so she is refused."""
    chain = FakeChain(bindings={MALLORY_LICENCE: "0x" + "cd" * 32})
    with pytest.raises(WrongInstanceLicenseError) as caught:
        assert_license_runs_this_instance(chain, LICENSE_TOKEN, MALLORY_LICENCE, INSTANCE)
    assert caught.value.this_instance == INSTANCE
    assert caught.value.bound_instance.lower() == ("0x" + "cd" * 32)


def test_case_differences_are_not_mismatches() -> None:
    chain = FakeChain(bindings={ALICE_LICENCE: INSTANCE})
    assert_license_runs_this_instance(
        chain, LICENSE_TOKEN, ALICE_LICENCE, INSTANCE.upper().replace("0X", "0x")
    )


# — version ids group licences; they are not licences —


def test_version_ids_differ_by_version_and_by_app() -> None:
    other_app = "0x3333333333333333333333333333333333333333"
    assert version_id_for(MANIFEST, "1.0.0") != version_id_for(MANIFEST, "2.0.0")
    assert version_id_for(MANIFEST, "1.0.0") != version_id_for(other_app, "1.0.0")


def test_version_ids_are_deterministic() -> None:
    assert version_id_for(MANIFEST, "1.0.0") == version_id_for(MANIFEST, "1.0.0")


def test_adjacent_version_strings_do_not_collide() -> None:
    assert version_id_for(MANIFEST, "1.0") != version_id_for(MANIFEST, "10")
