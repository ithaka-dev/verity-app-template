#!/usr/bin/env python3
"""Compare committed parity vectors against freshly emitted ones.

Everything is compared except ``seal.bundle``, which cannot be reproducible: ``seal()`` draws a
fresh ephemeral key on every call, and that is a security property rather than an inconvenience — a
fixed sender key would make one compromise open every bundle ever exported.

The committed bundle is therefore a **fixed artifact both implementations must be able to open**,
not a value to regenerate. That is asserted by ``ts/test/parity.test.ts`` and
``py/tests/test_parity.py``, which open it rather than recompute it. This script covers the rest:
the EIP-712 digests, the fingerprints and the token ids, all deterministic.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def without_bundle(document: dict[str, Any]) -> dict[str, Any]:
    copy: dict[str, Any] = json.loads(json.dumps(document))
    if isinstance(copy.get("seal"), dict):
        copy["seal"].pop("bundle", None)
    return copy


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as handle:
        committed = without_bundle(json.load(handle))
    with open(sys.argv[2], encoding="utf-8") as handle:
        emitted = without_bundle(json.load(handle))

    if committed == emitted:
        print("ok: parity vectors match the implementation")
        return 0

    print("::error::test-vectors/parity.json is stale.")
    for key in sorted(set(committed) | set(emitted)):
        if committed.get(key) != emitted.get(key):
            print(f"  differs: {key}")
            print(f"    committed: {json.dumps(committed.get(key))[:300]}")
            print(f"    emitted:   {json.dumps(emitted.get(key))[:300]}")
    print("If the wire contract changed on purpose, commit the regenerated file.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
