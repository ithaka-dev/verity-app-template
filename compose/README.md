# `app-compose.json`

**This file is the thing a licence binds to.** Not the image — the whole configuration. Its
SHA-256 is `composeHash`, which the platform measures into `MR-CONFIG-ID`, which a holder's
verifier compares against what their licence names. Every byte in here is covered.

Read [ADR 0006](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0006-appmanifest-version-record.md),
[ADR 0007](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0007-compose-must-pin-digests.md)
and [ADR 0009](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0009-verification-model.md)
before changing it.

---

## The one rule that is not negotiable

**Every image reference must be a digest. Never a tag.**

```yaml
image: ghcr.io/you/app@sha256:aabbcc…    # correct
image: ghcr.io/you/app:1.0.0             # WRONG — see below
image: ghcr.io/you/app:latest            # WRONG
```

A tag is a name the registry can repoint at any time. The compose text does not change when it
does, so `composeHash` stays stable, `MR-CONFIG-ID` stays stable, and attestation keeps passing —
while the code actually executing is whatever the registry currently serves.

**Every check succeeds and the guarantee is gone.** That is worse than a check that fails, because
nobody is looking. dStack's own reference compose gets this wrong, so treat it as a thing that
happens rather than an exotic mistake.

This is invariant I8. The publish script refuses a record whose `imageDigest` does not appear in
the compose, and the verifier cross-checks the same thing on the holder's side — that second one is
the enforcement a publisher cannot route around.

## Why the environment block is here and not injected

`VERITY_RPC_URL` decides who this app believes about who owns the licence. `VERITY_LICENSE_TOKEN`
decides which contract it asks. If either arrived at runtime, the attestation would say what code
runs while the code asks somebody unspecified what the chain says — and whoever answers decides who
the holder is.

Putting them here makes them part of `composeHash`, so a holder verifying before purchase is also
verifying the app's trust dependencies.

**The cost, accepted deliberately: changing any of these changes `composeHash`, which is a new
version holders must choose to move to.** An operator able to swap the RPC endpoint silently could
redirect the app's notion of ownership without anyone noticing. Inconvenience is the correct price.

## `public_logs: true`

Left at the platform default on purpose, because that is what developers will actually deploy with
and a template that quietly set it to `false` would teach people to expect privacy they do not
have.

Container stdout is retrievable by anyone who can reach the CVM's log endpoint. See
`ts/src/logging.ts`: print `fingerprint(domain, secret)`, never the value. A derived private key
was leaked into public logs during the experiment that produced this guidance, by someone who had
already designed the final test to avoid exactly that.

## The socket mount

```yaml
- /var/run/tappd.sock:/var/run/tappd.sock
```

`tappd.sock`, not `dstack.sock`. The latter returns 404 for every method on dstack 0.5.7 despite
appearing in current documentation. Re-verify on any version bump.

## The volume

```yaml
- app-data:/data
```

Encrypted, and **preserved across an in-place upgrade** — that is what makes `migrate` a data
*transformation* rather than a data *move* (ADR 0008).

The failure mode to understand is in [`docs/failure-modes.md`](../docs/failure-modes.md): a *fresh
deploy* produces a working instance with a new `app_id`, which derives different keys, which cannot
read anything the previous instance wrote. No error appears anywhere. The holder gets a healthy
empty app and finds out later.

## Before you publish

The zeroed digest and addresses above are placeholders and will not work. Fill in:

1. `image` — the real digest, from `docker buildx imagetools inspect` or the registry.
2. `VERITY_LICENSE_TOKEN`, `VERITY_APP_MANIFEST` — deployed addresses.
3. `VERITY_VERSION` — the version string you are publishing under. It must match the manifest
   record exactly; `tokenIdFor` derives from it, and a mismatch silently produces a `tokenId`
   nobody holds, so the app reports every real holder as unauthorized.

Then publish with the exact bytes of this file — **byte-identical** to what `composeURI` serves.
Not equivalent, not re-serialised. A pretty-printer between the two changes the hash.
