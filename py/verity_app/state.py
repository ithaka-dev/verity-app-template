"""The app's state on the encrypted volume, and the migrations that transform it.

Mirrors ``ts/src/state/``.

What the volume is
------------------
An in-place upgrade preserves ``app_id``, ``instance_id`` and **the encrypted volume itself** (ADR
0008, measured on real TDX). So ``migrate`` exists to *transform* data, never to move it — the bytes
are already there when the new version starts.

The failure mode of getting that wrong is silent: a *fresh deploy* produces a working instance with
a new ``app_id``, which derives different keys, which cannot read anything the previous instance
wrote. Nothing errors. The holder gets a healthy empty app and finds out later.

Idempotency, and why one mechanism is not enough
------------------------------------------------
The platform may retry — exactly-once delivery across a chain-and-enclave boundary is not
achievable, and requiring idempotency of apps is more honest than promising a guarantee that quietly
does not hold. An app written assuming exactly-once looks correct until the first retry.

Two mechanisms, because either alone is insufficient::

transform data        <- succeeded, volume now holds v2 write journal entry   <- process dies here

On retry the journal says nothing happened, so the transform runs again against already-migrated
data. The journal **cannot** close that window: there is no way to make "transform" and "record that
we transformed" atomic across two files. It narrows it; idempotent transforms make the remainder
harmless.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

CURRENT_SCHEMA_VERSION: Final = 2
PROFILES_DOCUMENT: Final = "profiles"
JOURNAL_DOCUMENT: Final = "migration-journal"
BOOT_RECORD_DOCUMENT: Final = "boot-record"


def DEFAULT_DATA_DIR() -> str:  # noqa: N802
    return os.environ.get("VERITY_DATA_DIR", "/data")


class StoreError(Exception):
    pass


class NoMigrationPathError(Exception):
    def __init__(self, from_version: int, to_version: int) -> None:
        super().__init__(f"no migration path from schema v{from_version} to v{to_version}")
        self.from_version = from_version
        self.to_version = to_version


@dataclass(frozen=True, slots=True)
class VersionedDocument:
    """A document with an explicit schema version.

    The version is stored *in the data*, not inferred from the app version. An app that infers it
    cannot tell an un-migrated volume from a migrated one after a retry, nor either from a rollback
    where the holder is deliberately running an older version against fresh state.
    """

    schema_version: int
    data: Any


class JsonStore:
    def __init__(self, data_dir: str | Path | None = None) -> None:
        # Resolved here rather than in the default argument: a default is evaluated once at import,
        # which would freeze whatever the environment happened to be when the module first loaded.
        self._dir = Path(data_dir if data_dir is not None else DEFAULT_DATA_DIR())

    def _path(self, name: str) -> Path:
        return self._dir / f"{name}.json"

    def read(self, name: str) -> VersionedDocument | None:
        path = self._path(name)
        try:
            raw = path.read_text()
        except FileNotFoundError:
            return None
        except OSError as err:
            raise StoreError(f"state at {path}: {err}") from err

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as err:
            # Refuse rather than treat unreadable state as absent. Returning None here would let a
            # corrupt volume look like a fresh one, and the app would start over on the holder's
            # data.
            raise StoreError(f"state at {path} is not valid JSON ({err})") from err

        if not isinstance(parsed, dict):
            raise StoreError(f"state at {path} is not a JSON object")
        version = parsed.get("schemaVersion")
        # `isinstance(True, int)` is True in Python, so a bare `bool` passed as a schema version and
        # migration ran from `True`. Integral floats are accepted because TypeScript writes JSON
        # numbers and is the writer this must interoperate with.
        if isinstance(version, bool) or not isinstance(version, (int, float)):
            raise StoreError(f"state at {path} has no numeric schemaVersion")
        if isinstance(version, float) and not version.is_integer():
            raise StoreError(f"state at {path} has a non-integral schemaVersion")
        return VersionedDocument(schema_version=int(version), data=parsed.get("data"))

    def write(self, name: str, document: VersionedDocument) -> None:
        """Write atomically: temp file, then rename.

        ``rename`` within a filesystem is atomic, so a crash — or a platform retry arriving
        mid-write — leaves either the old complete file or the new one, never half of either. A
        plain
        in-place write can leave truncated JSON that no version can read, turning a retryable
        failure
        into a permanent one.
        """
        path = self._path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        payload = {"schemaVersion": document.schema_version, "data": document.data}
        temporary.write_text(json.dumps(payload, indent=2) + "\n")
        temporary.replace(path)


def split_name(data: Any) -> dict[str, Any]:
    """v1 -> v2: split ``name`` into ``givenName`` / ``familyName``.

    Idempotent by construction: a record that already has ``givenName`` passes through untouched.
    Without that check, a second application reads ``name`` as missing and overwrites good data with
    empty strings — the exact damage a retry is supposed to be harmless.
    """
    if data is None or not isinstance(data, dict):
        # Silently rewriting unrecognised state is exactly the state loss this module is about.
        raise ValueError(f"expected a profiles document, got {type(data).__name__}")
    profiles = data.get("profiles", [])
    migrated = []
    for profile in profiles:
        if isinstance(profile.get("givenName"), str):
            migrated.append(profile)
            continue
        name = profile.get("name", "")
        # Refuse, do not guess. `str(None)` wrote the literal "None" into the holder's record, and
        # the idempotency check below then locked that in permanently — there is no down migration.
        if not isinstance(name, str):
            raise ValueError(
                f"profile {profile.get('id')!r} has a non-string `name` ({type(name).__name__}); "
                "refusing to transform data whose shape is not what this migration expects"
            )
        parts = name.strip().split()
        migrated.append(
            {
                "id": profile.get("id"),
                "givenName": parts[0] if parts else "",
                "familyName": " ".join(parts[1:]),
            }
        )
    return {"profiles": migrated}


# Steps are one-way. There is no ``down``, and that is a deliberate limitation: **backward state
# migration is not realistic** — v1 cannot read what v2 wrote, and no hook runs in reverse. Where a
# developer permits rollback the holder gets the old *version* with *fresh* state, and they must be
# told that before they choose it.
SCHEMA_STEPS: Final[tuple[tuple[int, int, Any], ...]] = ((1, 2, split_name),)


@dataclass(frozen=True, slots=True)
class MigrationOutcome:
    from_schema: int
    to_schema: int
    changed: bool


def migrate_profiles(store: JsonStore, target: int = CURRENT_SCHEMA_VERSION) -> MigrationOutcome:
    """Bring the stored document up to ``target``. Safe to call repeatedly."""
    document = store.read(PROFILES_DOCUMENT)

    if document is None:
        # A fresh instance is already at the current schema by definition — there is no data to
        # transform — so this is a success, not an error.
        store.write(PROFILES_DOCUMENT, VersionedDocument(target, {"profiles": []}))
        return MigrationOutcome(target, target, False)

    start = document.schema_version
    if start == target:
        return MigrationOutcome(start, target, False)
    if start > target:
        # An older build against newer data. Refuse loudly rather than "migrating" downward and
        # discarding fields the older version does not know about.
        raise NoMigrationPathError(start, target)

    current = document.data
    version = start
    while version < target:
        step = next((s for s in SCHEMA_STEPS if s[0] == version), None)
        if step is None:
            raise NoMigrationPathError(version, target)
        current = step[2](current)
        version = step[1]

    store.write(PROFILES_DOCUMENT, VersionedDocument(version, current))
    return MigrationOutcome(start, version, True)


# — the boot record —


def read_previous_compose_hash(store: JsonStore) -> str | None:
    """What this instance was running at its last successful start, or None on a first boot.

    A migration authorization names the version being migrated *from*. After an in-place upgrade the
    instance has already restarted on the new configuration, so the platform can say what is running
    now but has no memory of before. The only place that memory can live is the volume — which
    survives precisely because upgrade is in place.
    """
    document = store.read(BOOT_RECORD_DOCUMENT)
    if document is None:
        return None
    value = document.data.get("composeHash")
    return str(value) if isinstance(value, str) else None


def record_boot_compose_hash(store: JsonStore, compose_hash: str) -> None:
    """Record the currently running compose hash, after a successful start.

    A no-op when unchanged, so an ordinary restart does not overwrite the record of the version an
    outstanding migration is supposed to be coming *from*. Written after a successful start so a
    crash-looping version cannot overwrite the last known-good source.
    """
    existing = read_previous_compose_hash(store)
    if existing is not None and existing.lower() == compose_hash.lower():
        return
    store.write(BOOT_RECORD_DOCUMENT, VersionedDocument(1, {"composeHash": compose_hash}))


# — the migration journal —


def read_journal(store: JsonStore) -> dict[str, Any]:
    document = store.read(JOURNAL_DOCUMENT)
    return dict(document.data) if document is not None else {}


def record_attempt(store: JsonStore, nonce: int, from_digest: str, to_digest: str) -> None:
    journal = read_journal(store)
    journal[str(nonce)] = {"status": "in_flight", "fromDigest": from_digest, "toDigest": to_digest}
    store.write(JOURNAL_DOCUMENT, VersionedDocument(1, journal))


_TERMINAL_STATUSES: Final = frozenset({"complete", "failed"})


def record_outcome(store: JsonStore, nonce: int, status: str) -> None:
    """Record a terminal outcome.

    The status is validated against a closed set because its only consumer is an equality test
    against ``"complete"``. A typo such as ``"completed"`` does not fail — it silently disables the
    replay short-circuit, so the migration re-runs on every retry. TypeScript catches this at
    compile time via ``Exclude<JournalStatus, 'in_flight'>``; Python has to check.
    """
    if status not in _TERMINAL_STATUSES:
        raise ValueError(
            f"{status!r} is not a terminal journal status {sorted(_TERMINAL_STATUSES)}"
        )
    journal = read_journal(store)
    entry = journal.get(str(nonce))
    if entry is None:
        return
    entry["status"] = status
    store.write(JOURNAL_DOCUMENT, VersionedDocument(1, journal))
