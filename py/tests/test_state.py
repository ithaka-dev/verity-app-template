"""Migration behaviour, mirroring ``ts/test/migrations.test.ts``.

The two implementations must fail the same way as well as succeed the same way — an app that refuses
corrupt state in TypeScript and silently starts over in Python is two contracts, not one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verity_app.state import (
    CURRENT_SCHEMA_VERSION,
    PROFILES_DOCUMENT,
    JsonStore,
    NoMigrationPathError,
    StoreError,
    VersionedDocument,
    migrate_profiles,
    read_previous_compose_hash,
    record_boot_compose_hash,
    split_name,
)


@pytest.fixture
def store(tmp_path: Path) -> JsonStore:
    return JsonStore(tmp_path)


def test_migrates_v1_to_v2(store: JsonStore) -> None:
    store.write(
        PROFILES_DOCUMENT, VersionedDocument(1, {"profiles": [{"id": "a", "name": "Ada Lovelace"}]})
    )

    outcome = migrate_profiles(store)
    assert outcome.changed is True
    assert outcome.to_schema == CURRENT_SCHEMA_VERSION

    document = store.read(PROFILES_DOCUMENT)
    assert document is not None
    assert document.data["profiles"] == [{"id": "a", "givenName": "Ada", "familyName": "Lovelace"}]


def test_migrating_twice_produces_identical_data(store: JsonStore) -> None:
    """The property the platform's retry behaviour depends on. Not "it does not crash" — the data
    must be *identical*, because a second pass that mangles already-migrated records is the exact
    damage a retry is supposed to be harmless."""
    store.write(
        PROFILES_DOCUMENT,
        VersionedDocument(
            1, {"profiles": [{"id": "a", "name": "Ada Lovelace"}, {"id": "b", "name": "Grace"}]}
        ),
    )

    migrate_profiles(store)
    after_first = store.read(PROFILES_DOCUMENT)

    second = migrate_profiles(store)
    after_second = store.read(PROFILES_DOCUMENT)

    assert second.changed is False
    assert after_second == after_first


def test_the_transform_is_safe_on_already_migrated_data() -> None:
    """The window the journal cannot close: the transform succeeded, the journal write did not, and
    the retry runs the transform against already-migrated data."""
    migrated = {"profiles": [{"id": "a", "givenName": "Ada", "familyName": "Lovelace"}]}
    assert split_name(migrated) == migrated


def test_a_name_with_no_surname_does_not_invent_one() -> None:
    assert split_name({"profiles": [{"id": "b", "name": "Grace"}]})["profiles"] == [
        {"id": "b", "givenName": "Grace", "familyName": ""}
    ]


def test_a_fresh_volume_is_initialised_at_the_current_schema(store: JsonStore) -> None:
    outcome = migrate_profiles(store)
    assert outcome.changed is False
    document = store.read(PROFILES_DOCUMENT)
    assert document is not None
    assert document.schema_version == CURRENT_SCHEMA_VERSION


def test_refuses_to_migrate_backwards(store: JsonStore) -> None:
    store.write(PROFILES_DOCUMENT, VersionedDocument(99, {"profiles": []}))
    with pytest.raises(NoMigrationPathError):
        migrate_profiles(store)


def test_refuses_to_migrate_across_a_gap(store: JsonStore) -> None:
    store.write(PROFILES_DOCUMENT, VersionedDocument(0, {"profiles": []}))
    with pytest.raises(NoMigrationPathError):
        migrate_profiles(store)


def test_unreadable_state_is_refused_not_treated_as_absent(
    store: JsonStore, tmp_path: Path
) -> None:
    """Corrupt state must not look like a fresh volume. If it did, the app would start over on top
    of the holder's data and report success."""
    (tmp_path / f"{PROFILES_DOCUMENT}.json").write_text("{not json")
    with pytest.raises(StoreError):
        store.read(PROFILES_DOCUMENT)


def test_state_without_a_schema_version_is_refused(store: JsonStore, tmp_path: Path) -> None:
    (tmp_path / f"{PROFILES_DOCUMENT}.json").write_text('{"data": {}}')
    with pytest.raises(StoreError):
        store.read(PROFILES_DOCUMENT)


def test_writes_leave_no_temporary_file(store: JsonStore, tmp_path: Path) -> None:
    store.write(PROFILES_DOCUMENT, VersionedDocument(2, {"profiles": []}))
    assert not (tmp_path / f"{PROFILES_DOCUMENT}.json.tmp").exists()


def test_boot_record_round_trips(store: JsonStore) -> None:
    assert read_previous_compose_hash(store) is None
    record_boot_compose_hash(store, "0xabc")
    assert read_previous_compose_hash(store) == "0xabc"


def test_an_unchanged_restart_does_not_overwrite_the_boot_record(store: JsonStore) -> None:
    """Otherwise an ordinary restart erases the record of the version an outstanding migration is
    supposed to be coming from."""
    record_boot_compose_hash(store, "0xabc")
    record_boot_compose_hash(store, "0xABC")
    assert read_previous_compose_hash(store) == "0xabc"
