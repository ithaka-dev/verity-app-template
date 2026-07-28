# Failure modes

**Status:** active

What breaks, what the platform guarantees, and what your app is responsible for. Written because an
interface nobody implements correctly is worse than none — the platform starts making promises the
apps do not keep.

Read this before shipping a level-2 app. Most of it is about failures that produce a *working*
system rather than an error.

---

## 1. Fresh deploy instead of in-place upgrade — silent total data loss

**The worst one, and the least visible.**

State continuity follows `app_id`, not `compose_hash`. An in-place upgrade preserves `app_id`,
`instance_id` and the encrypted volume. A *fresh deploy* gets a new `app_id`, which derives
different KMS keys, which cannot read anything the previous instance wrote.

Nothing errors. Nothing in the attestation is wrong. The instance comes up **healthy and empty**,
and the holder discovers it later.

| | in-place upgrade | fresh deploy |
|---|---|---|
| `app_id` | preserved | new |
| encrypted volume | carried over | empty |
| derived keys | same | different |
| observable failure | — | **none** |

Measured on dstack 0.5.7. **Re-verify on any version bump**, because the failure mode of a silent
regression here is losing holders' data with no signal.

*What your app can do:* record the compose hash at each successful start (`state/boot-record.ts`).
An instance that finds an empty volume where it expected data is either brand new or has been
through this — and it can at least say so in `health` rather than reporting `ok`.

## 2. `migrate` fails halfway

The platform may retry. Your transform must tolerate being applied to data it has already
transformed.

The window that catches people:

```
transform data        ← succeeded, volume now holds v2
write journal entry   ← process dies here
```

On retry the journal says nothing happened, so the transform runs again against already-migrated
data. **The journal cannot close this window** — there is no way to make "transform" and "record
that we transformed" atomic across two files. It narrows it; idempotent transforms are what make
the remainder harmless.

*What your app must do:*

- Store the schema version **inside the document**, not inferred from the app version. Inference
  cannot distinguish an un-migrated volume from a migrated one after a retry, nor either from a
  rollback where the holder is deliberately running an older version against fresh state.
- Write a step that checks before it converts. `splitName` in `state/migrations.ts` passes through
  any record that already has the target shape; without that, a second pass reads the source field
  as `undefined` and overwrites good data with empty strings.
- Write atomically — temp file, then rename. A plain in-place write can leave truncated JSON that
  no version can read, turning a retryable failure into a permanent one.

*What you may assume:* the volume is intact and holds exactly what the previous version left. The
platform does not clear it, move it, or partially restore it.

*What you may not assume:* that `migrate` runs exactly once, that it runs before any request
arrives, or that a previous attempt got no further than it appeared to.

## 3. Migration is refused

`migrate` returns `failed` with a reason. The common causes, in the order they are checked:

| Cause | What it means |
|---|---|
| no compose hash from the platform | the app cannot verify `toDigest` against what is running, so it refuses rather than trusting the message about itself |
| `instanceId` mismatch | a genuine signature for a *different* instance the same holder owns |
| `toDigest` mismatch | the authorization is for a version this instance is not running |
| `fromDigest` mismatch | the source version is not what this instance last booted |
| expired | outside the window the holder signed for |
| signature invalid | not signed by the account claimed |
| smart account | ERC-1271 is not implemented in MVP — a known gap, not a signature failure |
| not the current holder | the signer holds none of this licence *now* |

That last one is the one worth understanding: it is what selling a licence looks like from the
app's side. Licences transfer (spec §2.6), and the previous holder's signature stays
cryptographically valid forever. Resolving the holder from chain state on every call is what stops
them from authorizing migrations on an instance they sold.

## 4. `needs_holder_action`

Your migration cannot proceed without a decision only the owner can make — a destructive
transformation, a choice between schemas.

Return it rather than guessing or failing. It reaches the holder through the orchestrator and the
upgrade flow, **never directly**: your app sits inside a CVM behind an endpoint the holder may never
call, so there is no direct channel to use.

**Emit it as telemetry too.** An instance parked in `needs_holder_action` is indistinguishable from
a slow migration until somebody looks, and nobody looks.

## 5. Rollback: old version, fresh state

Where a developer permits downgrades, the holder gets the old **version** with **fresh state**.

Backward migration is not realistic and the platform does not attempt it: v1.0 cannot read what
v1.1 wrote, and no hook runs in reverse. There is no `down` step in `state/migrations.ts` and that
is deliberate.

**A developer advertising rollback without saying this is promising something the platform does not
deliver.** Put it in your own documentation.

## 6. The guest agent is unreachable

Every lifecycle call needs it. If `tappd.sock` does not answer:

- Check the socket is mounted (`compose/README.md`).
- Check the name. `dstack.sock` 404s on 0.5.7 despite appearing in current documentation — a 404
  from the guest agent almost always means the wrong socket rather than a missing method.
- The client sets an explicit timeout. An agent that accepts a connection and then stalls would
  otherwise hang a health check forever, and "forever" is indistinguishable from "unhealthy" only
  after someone notices.

## 7. Chain reads fail

The RPC endpoint is pinned in the compose and therefore measured. If it is down, holder resolution
fails and `migrate` refuses.

**Refusing is correct.** The alternative — proceeding on a cached or assumed holder — is how a
previous holder's authorization gets accepted. A migration deferred costs a retry; a migration
authorized by the wrong person costs the holder their data.

Do not add a fallback endpoint that is not in the compose. It would be an unmeasured trust
dependency, which is the thing pinning exists to prevent.

## 8. Things that must never happen

Not failure modes — prohibitions. An implementation that does any of these is wrong regardless of
how well it works.

- **Migrating because a mint was observed.** Minting says "I want this version." Migration says
  "move this instance's data." They are separate holder acts (I10), and a holder may legitimately
  want the new version without their running instance being touched.
- **Exporting unasked.** Same reasoning (ADR 0010).
- **Trusting the orchestrator's word.** It relays a holder-signed fact; it does not author one. An
  authenticated channel to it would not change this — a secure channel establishes *who is
  speaking*, not *that what they say is authorized*.
- **Comparing the signer against a deploy-time owner.** See §3.
- **Logging a secret.** See `ts/src/logging.ts`.

## 9. What attestation does and does not prove

It proves *what code runs*. It does not prove *that the code honours its interface*.

A level-2 declaration is the developer's claim. Measurement can prove the shape is present —
declared capabilities are part of the measured configuration — but not that `migrate` does anything
sensible with your data.

This is the same trust posture as everything else here: the platform guarantees *what you licensed
is what runs*, never *what you licensed is good*. Conformance testing at publish time can raise
confidence; it cannot make it a guarantee, and no documentation should imply otherwise.
