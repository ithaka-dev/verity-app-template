# verity-app-template

> ## 🚧 Not functional — do not adopt
>
> This repository is **scaffolding**. It does not yet do the thing its description says it does.
> Nothing here is ready to depend on, build against, or copy.
>
> **Copying this now defeats its purpose.** The template's value is that it demonstrates the
> patterns correctly the first time, because apps built on it cannot be patched afterwards. An
> incomplete template teaches incomplete patterns to every app that clones it.
>
> **Readiness is per-repo and will be announced by removing this banner** and tagging a release.
> Until then, treat anything here as subject to change without notice — including its public
> interface, its behaviour, and its existence.
>
> Sequence and current position: [`plan.md`](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md).

Reference implementation of the app lifecycle contract — `health`, `migrate`, `export` — over the dStack guest agent.

**Language:** TypeScript and Python
**Phase:** 2 of the [implementation plan](https://github.com/ithaka-dev/verity-foundation/blob/main/plan.md)

---

## Read before contributing

Every constraint that makes Verity work lives in
**[verity-foundation](https://github.com/ithaka-dev/verity-foundation)** — the specification, the
architecture decisions, the invariants, and the measured facts they rest on. This repository holds
an implementation of decisions made there, not the decisions themselves.

- [Specification](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/Verity-spec.md) — start here; §7 holds the invariants
- [Decisions (ADRs)](https://github.com/ithaka-dev/verity-foundation/tree/main/docs/decisions) — why things are the way they are
- [`CLAUDE.md`](CLAUDE.md) — what binds *this* repository specifically

**If a decision seems missing, it probably isn't — go and find it.** If it genuinely is missing,
it belongs in an ADR in `verity-foundation`, not in a pull request here.

## Boundary

**The highest-leverage artifact in the project, and the least patchable.** Once developers copy this, its mistakes ship in every app built on it and no later decision fixes them. Per [ADR 0005](https://github.com/ithaka-dev/verity-foundation/blob/main/docs/decisions/0005-design-for-smart-accounts-implement-eoa.md), **review it harder than internal code, not less.**

- Guest agent lives on `tappd.sock`; `dstack.sock` 404s on dstack 0.5.7 (measured).
- **Derive-and-fingerprint is the only logging pattern demonstrated.** `public_logs` defaults to `true`, and a derived key printed into logs is a disclosed key.
- Signature verification dispatches on account type even though only the EOA branch is reachable in MVP.
- The TypeScript and Python implementations must not drift — they teach the same contract or they teach two.
