/**
 * The TypeScript half of the parity contract.
 *
 * ## Why this file exists, and what its absence cost
 *
 * `test-vectors/parity.json` is emitted from *this* implementation, and for a while only the Python
 * suite asserted against it. That is not parity — it makes TypeScript the oracle, and an oracle
 * cannot be wrong by construction.
 *
 * A review demonstrated it: changing the HKDF `info` string in `src/seal.ts` broke the seal binding
 * so that the two languages produced mutually unopenable bundles, and **both suites stayed green**.
 * The vector file's own description claimed both sides were checked against it. They were not.
 *
 * So these tests pin this implementation to the committed vectors. Regenerating the file is now a
 * deliberate act with a visible diff (`ts/scripts/emit-vectors.ts`); if a change here produces a
 * diff you did not intend, that diff is the bug report.
 */

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

import type {Address, Hex} from 'viem';

import {hashExportAuthorization, hashMigrationAuthorization} from '../src/authorization.ts';
import {fingerprint, type FingerprintDomain} from '../src/logging.ts';
import {versionIdFor} from '../src/holder.ts';
import {open, type SealedBundle} from '../src/seal.ts';

interface Parity {
  readonly eip712: {
    readonly domain: {readonly chainId: number; readonly verifyingContract: Address};
    readonly migration: {readonly message: Record<string, string>; readonly digest: Hex};
    readonly export: {readonly message: Record<string, string>; readonly digest: Hex};
  };
  readonly fingerprints: ReadonlyArray<{domain: string; secret: string; value: string}>;
  readonly seal: {
    readonly recipientPrivateKeyHex: string;
    readonly recipientPublicKeyHex: string;
    readonly context: {readonly licenseId: string; readonly instanceId: string};
    readonly plaintext: string;
    readonly bundle: SealedBundle;
  };
  readonly versionIds: ReadonlyArray<{appManifest: Address; version: string; versionId: string}>;
}

const VECTORS = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../test-vectors/parity.json', import.meta.url)), 'utf8'),
) as Parity;

test('the migration digest matches the committed vector', () => {
  const m = VECTORS.eip712.migration.message;
  const digest = hashMigrationAuthorization(
    {
      licenseId: BigInt(m.licenseId!),
      fromDigest: m.fromDigest as Hex,
      toDigest: m.toDigest as Hex,
      instanceId: m.instanceId as Hex,
      nonce: BigInt(m.nonce!),
      expiry: BigInt(m.expiry!),
    },
    VECTORS.eip712.domain.chainId,
    VECTORS.eip712.domain.verifyingContract,
  );
  assert.equal(digest, VECTORS.eip712.migration.digest);
});

test('the export digest matches the committed vector', () => {
  const e = VECTORS.eip712.export.message;
  const digest = hashExportAuthorization(
    {
      licenseId: BigInt(e.licenseId!),
      instanceId: e.instanceId as Hex,
      recipientPublicKey: e.recipientPublicKey as Hex,
      nonce: BigInt(e.nonce!),
      expiry: BigInt(e.expiry!),
    },
    VECTORS.eip712.domain.chainId,
    VECTORS.eip712.domain.verifyingContract,
  );
  assert.equal(digest, VECTORS.eip712.export.digest);
});

test('fingerprints match the committed vectors', () => {
  for (const vector of VECTORS.fingerprints) {
    assert.equal(
      fingerprint(vector.domain as FingerprintDomain, vector.secret),
      vector.value,
      vector.domain,
    );
  }
});

test('version ids match the committed vectors', () => {
  for (const vector of VECTORS.versionIds) {
    assert.equal(versionIdFor(vector.appManifest, vector.version), BigInt(vector.versionId));
  }
});

/**
 * The test whose absence let a broken HKDF binding ship green.
 *
 * It opens the *committed* bundle rather than one produced in this run, so a change to the seal
 * construction fails here instead of silently producing bundles no existing holder tool can read.
 */
test('the committed bundle still opens under this implementation', async () => {
  const {createPrivateKey} = await import('node:crypto');
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(VECTORS.seal.recipientPrivateKeyHex, 'hex'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  const plaintext = open(VECTORS.seal.bundle, privateKey, {
    licenseId: BigInt(VECTORS.seal.context.licenseId),
    instanceId: VECTORS.seal.context.instanceId,
  });
  assert.equal(plaintext.toString('utf8'), VECTORS.seal.plaintext);
});

/** Guards the fixture: a mismatched pair would make the test above vacuous rather than failing. */
test('the vector keypair is internally consistent', async () => {
  const {createPrivateKey, createPublicKey} = await import('node:crypto');
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(VECTORS.seal.recipientPrivateKeyHex, 'hex'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const derived = Buffer.from(
    createPublicKey(privateKey).export({format: 'der', type: 'spki'}).subarray(-32),
  ).toString('hex');
  assert.equal(derived, VECTORS.seal.recipientPublicKeyHex);
});
