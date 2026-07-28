/**
 * Regenerate `test-vectors/parity.json` from the TypeScript implementation.
 *
 * The TypeScript side is the source of the vectors and both sides are then tested against the file,
 * so neither implementation can quietly become the other's oracle. Run this only when a *deliberate*
 * change to the wire contract is being made — if it produces a diff you did not intend, that diff is
 * the bug report.
 *
 *     node --experimental-strip-types ts/scripts/emit-vectors.ts > test-vectors/parity.json
 */

import {createPrivateKey, createPublicKey} from 'node:crypto';

import type {Address, Hex} from 'viem';

import {hashExportAuthorization, hashMigrationAuthorization} from '../src/authorization.ts';
import {tokenIdFor} from '../src/holder.ts';
import {fingerprint} from '../src/logging.ts';
import {seal} from '../src/seal.ts';

const licenseToken = '0x1111111111111111111111111111111111111111' as Address;
const appManifest = '0x1111111111111111111111111111111111111111' as Address;
const chainId = 84532;

const migration = {
  licenseId: 42n,
  fromDigest: `0x${'ab'.repeat(32)}` as Hex,
  toDigest: `0x${'cd'.repeat(32)}` as Hex,
  instanceId: `0x${'00'.repeat(31)}ff` as Hex,
  nonce: 7n,
  expiry: 4_000_000_000n,
};

const exported = {
  licenseId: 42n,
  instanceId: `0x${'00'.repeat(31)}ff` as Hex,
  recipientPublicKey: `0x${'ee'.repeat(32)}` as Hex,
  nonce: 7n,
  expiry: 4_000_000_000n,
};

const decimalise = <T extends Record<string, unknown>>(message: T): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(message).map(([k, v]) => [k, typeof v === 'bigint' ? v.toString() : v]),
  );

/**
 * A fixed test recipient key, so the sealed bundle below is openable from any language.
 *
 * This is a published private key in a test fixture. It is deliberately not generated: the point of
 * the vector is that a *different implementation* can open a bundle it did not create, which is only
 * demonstrable if both sides can hold the same private half.
 */
const RECIPIENT_PRIVATE_HEX =
  '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';

const recipientPrivate = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'),
    Buffer.from(RECIPIENT_PRIVATE_HEX, 'hex'),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const recipientPublicHex = Buffer.from(
  createPublicKey(recipientPrivate).export({format: 'der', type: 'spki'}).subarray(-32),
).toString('hex');

const SEAL_PLAINTEXT = 'the holder\u2019s data, sealed in the enclave';
const sealContext = {licenseId: 42n, instanceId: '0x00000000000000000000000000000000000000ff'};
const sealedBundle = seal(
  new TextEncoder().encode(SEAL_PLAINTEXT),
  createPublicKey(recipientPrivate),
  sealContext,
);

const document = {
  description:
    'Cross-language parity vectors. TypeScript and Python must reproduce every value here exactly.',
  source:
    'Emitted from the TypeScript implementation by ts/scripts/emit-vectors.ts, then both sides are ' +
    'tested against this file so neither becomes the other’s oracle. The EIP-712 digests are the ' +
    'authority: a signature is verified against them, so a language computing a different digest ' +
    'silently rejects every genuine holder signature.',
  why:
    'The two implementations teach the same contract or they teach two. Drift here does not fail ' +
    'loudly — it produces an app that refuses its own holder, three layers from the cause.',
  eip712: {
    domain: {
      name: 'Verity App Lifecycle',
      version: '1',
      chainId,
      verifyingContract: licenseToken,
    },
    migration: {
      message: decimalise(migration),
      digest: hashMigrationAuthorization(migration, chainId, licenseToken),
    },
    export: {
      message: decimalise(exported),
      digest: hashExportAuthorization(exported, chainId, licenseToken),
    },
  },
  fingerprints: [
    {domain: 'derived-key', secret: 'hunter2', value: fingerprint('derived-key', 'hunter2')},
    {domain: 'migration-nonce', secret: 'hunter2', value: fingerprint('migration-nonce', 'hunter2')},
    {domain: 'export-key', secret: '', value: fingerprint('export-key', '')},
  ],
  seal: {
    note:
      'A bundle sealed by the TypeScript implementation. Python must open it and recover ' +
      'plaintext exactly — that is what proves the two constructions are the same one, rather ' +
      'than two that merely both work.',
    recipientPrivateKeyHex: RECIPIENT_PRIVATE_HEX,
    recipientPublicKeyHex: recipientPublicHex,
    context: {licenseId: sealContext.licenseId.toString(), instanceId: sealContext.instanceId},
    plaintext: SEAL_PLAINTEXT,
    bundle: sealedBundle,
  },
  tokenIds: [
    {
      appManifest,
      version: '1.0.0',
      tokenId: `0x${tokenIdFor(appManifest, '1.0.0').toString(16).padStart(64, '0')}`,
    },
  ],
};

process.stdout.write(`${JSON.stringify(document, null, 2)}\n`);
