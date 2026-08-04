/**
 * T-07: the TypeScript half of the *behavioural* parity contract.
 *
 * `parity.json` pins what the two languages compute. This pins what they decide. The gap between
 * those was not hypothetical: both implementations produced byte-identical EIP-712 digests for an
 * authorization expiring in the year 2100 — agreeing on every digest, fingerprint and token id in
 * `parity.json` — and then TypeScript refused it while Python honoured it. No value vector could
 * have caught that, because no value differed.
 *
 * Each case names its expected outcome as a language-neutral reason, which each side maps to its
 * own error type. That mapping is the point: it catches a language that refuses for the *wrong*
 * reason, not only one that fails to refuse. Ordering is behaviour too — a language that checks
 * fields before the clock reports a stale authorization as a mismatch, and sends whoever reads the
 * log after the wrong bug.
 *
 * The case table is hand-written and must stay that way. `parity.json` is emitted from this
 * implementation and its header records the cost: for a while only Python asserted against it,
 * which made TypeScript an oracle, and an oracle cannot be wrong by construction. A behaviour table
 * generated from either side would encode that side's bugs as the contract.
 */

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

import type {Hex} from 'viem';

import {
  assertAuthorizationMatches,
  assertExportAuthorizationMatches,
  AuthorizationExpiredError,
  AuthorizationLifetimeTooLongError,
  AuthorizationMismatchError,
  MAX_AUTHORIZATION_LIFETIME_SECONDS,
  type ExportAuthorization,
  type MigrationAuthorization,
} from '../src/authorization.ts';

interface MigrationCase {
  readonly name: string;
  readonly now: number;
  readonly authorization: {
    licenseId: number;
    fromDigest: Hex;
    toDigest: Hex;
    instanceId: Hex;
    nonce: number;
    expiry: number;
  };
  readonly expected: {
    runningComposeHash: Hex;
    previousComposeHash: Hex | null;
    instanceId: Hex;
  };
  readonly outcome: 'accept' | 'reject';
  readonly reason?: string;
}

interface ExportCase {
  readonly name: string;
  readonly now: number;
  readonly authorization: {
    licenseId: number;
    instanceId: Hex;
    recipientPublicKey: Hex;
    nonce: number;
    expiry: number;
  };
  readonly expectedInstanceId: Hex;
  readonly outcome: 'accept' | 'reject';
  readonly reason?: string;
}

interface Behaviour {
  readonly constants: {readonly maxAuthorizationLifetimeSeconds: number};
  readonly migration: readonly MigrationCase[];
  readonly export: readonly ExportCase[];
}

const behaviour: Behaviour = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../test-vectors/behaviour.json', import.meta.url)), 'utf8'),
) as Behaviour;

/**
 * Translate a thrown error into the table's language-neutral reason.
 *
 * Returns `null` for anything unrecognised rather than a catch-all string, so an unexpected error
 * type fails loudly instead of being folded into whatever the case expected.
 */
function reasonFor(error: unknown): string | null {
  if (error instanceof AuthorizationExpiredError) return 'AuthorizationExpired';
  if (error instanceof AuthorizationLifetimeTooLongError) return 'AuthorizationLifetimeTooLong';
  if (error instanceof AuthorizationMismatchError) return `AuthorizationMismatch:${error.field}`;
  return null;
}

/** Run one case and assert the outcome, whatever shape it takes. */
function check(name: string, run: () => void, expected: MigrationCase | ExportCase): void {
  let thrown: unknown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }

  if (expected.outcome === 'accept') {
    assert.equal(thrown, undefined, `${name}: expected acceptance, got ${String(thrown)}`);
    return;
  }

  assert.notEqual(thrown, undefined, `${name}: expected refusal (${expected.reason}), got none`);
  const actual = reasonFor(thrown);
  assert.notEqual(
    actual,
    null,
    `${name}: refused with an error the parity table does not name: ${String(thrown)}`,
  );
  assert.equal(actual, expected.reason, `${name}: refused for the wrong reason`);
}

function toMigration(c: MigrationCase): MigrationAuthorization {
  return {
    licenseId: BigInt(c.authorization.licenseId),
    fromDigest: c.authorization.fromDigest,
    toDigest: c.authorization.toDigest,
    instanceId: c.authorization.instanceId,
    nonce: BigInt(c.authorization.nonce),
    expiry: BigInt(c.authorization.expiry),
  };
}

function toExport(c: ExportCase): ExportAuthorization {
  return {
    licenseId: BigInt(c.authorization.licenseId),
    instanceId: c.authorization.instanceId,
    recipientPublicKey: c.authorization.recipientPublicKey,
    nonce: BigInt(c.authorization.nonce),
    expiry: BigInt(c.authorization.expiry),
  };
}

for (const c of behaviour.migration) {
  test(`migration parity: ${c.name}`, () => {
    check(
      c.name,
      () =>
        assertAuthorizationMatches(
          toMigration(c),
          {
            runningComposeHash: c.expected.runningComposeHash,
            previousComposeHash: c.expected.previousComposeHash,
            instanceId: c.expected.instanceId,
          },
          BigInt(c.now),
        ),
      c,
    );
  });
}

for (const c of behaviour.export) {
  test(`export parity: ${c.name}`, () => {
    check(
      c.name,
      () => assertExportAuthorizationMatches(toExport(c), c.expectedInstanceId, BigInt(c.now)),
      c,
    );
  });
}

/**
 * The table states the constant it builds its boundary cases around. If an implementation changes
 * it, those cases stop testing a boundary and start testing an arbitrary interior point — silently,
 * and while still passing.
 */
test('the lifetime constant matches the one the table assumes', () => {
  assert.equal(
    MAX_AUTHORIZATION_LIFETIME_SECONDS,
    BigInt(behaviour.constants.maxAuthorizationLifetimeSeconds),
  );
});

/**
 * A table that quietly shrank would keep passing. Both suites assert the count, so deleting an
 * inconvenient case has to be done twice and shows up in both diffs.
 */
test('every case in the table was run', () => {
  assert.equal(behaviour.migration.length, 14);
  assert.equal(behaviour.export.length, 5);
});
