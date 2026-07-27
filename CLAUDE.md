# verity-app-template — agent instructions

**This repository implements decisions made in
[verity-foundation](https://github.com/ithaka-dev/verity-foundation/blob/main/../..). It does not make them.**

Before substantive work, read:
1. [`docs/Verity-spec.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — §7 holds the ten invariants
2. [`docs/decisions/`](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions) — the ADRs listed below bind this repo directly
3. [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md) — where this repo's issues sit in the sequence

**If something here seems undecided, it probably isn't.** Search the ADRs before deciding it in a
pull request. If it is genuinely undecided, it belongs in an ADR upstream — not in code here.

## Binding decisions

[ADR 0005](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0005-design-for-smart-accounts-implement-eoa.md) ·
[ADR 0008](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0008-upgrade-is-in-place.md) ·
[ADR 0010](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0010-export-capability.md) ·
[RFC app-lifecycle-contract](https://github.com/ithaka-dev/verity-foundation/blob/main/records/rfcs/2026-07-25-app-lifecycle-contract.md)

## Why this repo is different

**Unpatchable once copied.** Developers will clone this and ship it. A mistake here ships in every
app built on it, and no later decision fixes them. ADR 0005 is explicit: **review this harder than
internal code, not less.** That inverts the usual instinct that examples deserve less scrutiny.

## Hard rules

- **Guest agent is on `tappd.sock`.** `dstack.sock` returns 404 for every method on dstack 0.5.7 (measured).
- **Derive-and-fingerprint is the only logging pattern demonstrated.** `public_logs` defaults to `true`. Print `sha256("fp|" ‖ key)`, never the key, and never the value used as a passphrase. This is not theoretical — a derived private key was leaked into public logs during the experiment that produced this guidance, by someone who had already designed the final test to avoid exactly that.
- **Signature verification dispatches on account type**, even though only the EOA branch is reachable in MVP. A template teaching bare `ecrecover` breaks every app built on it at the mainnet gate.
- **Resolve the current holder from chain state**, not a deploy-time owner. Licenses transfer — a baked-in owner lets a *previous* holder authorize actions after selling.
- **Pin the RPC endpoint in the compose**, so the app's trust dependency is measured and visible before purchase.
- **`migrate` transforms data; it does not move it.** The volume carries over by itself on an in-place upgrade. `migrate` exists only for schema changes.
- **Apps must be idempotent** — the platform may retry.
- **No auto-anything.** Never migrate on observing a mint; never export unasked (I10, ADR 0010).

## Two implementations

TypeScript and Python must not drift. They teach the same contract or they teach two. A change to
one is incomplete until the other matches, and shared test vectors are what keep that honest.
