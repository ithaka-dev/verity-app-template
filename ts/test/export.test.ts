import assert from 'node:assert/strict';
import {mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';

import type {Address, Hex, PublicClient} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';

import {
  EXPORT_AUTHORIZATION_TYPES,
  MIGRATION_AUTHORIZATION_TYPES,
  migrationDomain,
  type ExportAuthorization,
} from '../src/authorization.ts';
import type {AppConfig} from '../src/config.ts';
import {exportState} from '../src/handlers/export.ts';
import type {GuestAgent} from '../src/guest-agent.ts';
import {toBytes32} from '../src/handlers/migrate.ts';
import {SealError, generateRecipientKeypair, open, parseRecipientKey, seal} from '../src/seal.ts';
import {PROFILES_DOCUMENT} from '../src/state/migrations.ts';
import {JsonStore} from '../src/state/store.ts';

const HOLDER = privateKeyToAccount(`0x${'11'.repeat(32)}`);
const STRANGER = privateKeyToAccount(`0x${'22'.repeat(32)}`);
const INSTANCE_ID = '0x00000000000000000000000000000000000000000000000000000000000000ff';

const CONFIG: AppConfig = {
  chainId: 84532,
  rpcUrl: 'https://example.invalid',
  licenseToken: '0x1111111111111111111111111111111111111111',
  appManifest: '0x2222222222222222222222222222222222222222',
  version: '1.0.0',
  publicLogs: true,
};

function fakeGuestAgent(): GuestAgent {
  return {
    info: async () => ({appId: '0xapp', instanceId: INSTANCE_ID, composeHash: `0x${'ab'.repeat(32)}`}),
  } as unknown as GuestAgent;
}

function fakeClient(options: {balance: bigint; code?: Hex}): PublicClient {
  return {
    getCode: async () => options.code,
    readContract: async () => options.balance,
  } as unknown as PublicClient;
}

// — the sealing construction —

test('the holder can open what was sealed to them', () => {
  const {publicKeyHex, privateKey} = generateRecipientKeypair();
  const context = {licenseId: 42n, instanceId: INSTANCE_ID};
  const bundle = seal(new TextEncoder().encode('secret state'), parseRecipientKey(publicKeyHex), context);
  assert.equal(open(bundle, privateKey, context).toString('utf8'), 'secret state');
});

/** An export that cannot be opened is worse than no export — it is discovered when the data is needed. */
test('a different holder key cannot open the bundle', () => {
  const mine = generateRecipientKeypair();
  const theirs = generateRecipientKeypair();
  const context = {licenseId: 42n, instanceId: INSTANCE_ID};
  const bundle = seal(new TextEncoder().encode('secret'), parseRecipientKey(mine.publicKeyHex), context);
  assert.throws(() => open(bundle, theirs.privateKey, context), SealError);
});

/** The context is inside the derived key, so a bundle cannot be passed off as another export. */
test('a bundle does not open under a different context', () => {
  const {publicKeyHex, privateKey} = generateRecipientKeypair();
  const bundle = seal(
    new TextEncoder().encode('secret'),
    parseRecipientKey(publicKeyHex),
    {licenseId: 42n, instanceId: INSTANCE_ID},
  );
  assert.throws(
    () => open(bundle, privateKey, {licenseId: 43n, instanceId: INSTANCE_ID}),
    SealError,
  );
  assert.throws(
    () => open(bundle, privateKey, {licenseId: 42n, instanceId: '0xdead'}),
    SealError,
  );
});

test('tampering with the ciphertext is detected', () => {
  const {publicKeyHex, privateKey} = generateRecipientKeypair();
  const context = {licenseId: 1n, instanceId: INSTANCE_ID};
  const bundle = seal(new TextEncoder().encode('secret'), parseRecipientKey(publicKeyHex), context);

  const raw = Buffer.from(bundle.ciphertext, 'base64');
  raw[0] = (raw[0] ?? 0) ^ 0x01;
  const tampered = {...bundle, ciphertext: raw.toString('base64')};

  assert.throws(() => open(tampered, privateKey, context), SealError);
});

/** Forward secrecy: one compromise must not open every past bundle. */
test('each seal uses a fresh ephemeral key', () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const recipient = parseRecipientKey(publicKeyHex);
  const context = {licenseId: 1n, instanceId: INSTANCE_ID};
  const a = seal(new TextEncoder().encode('x'), recipient, context);
  const b = seal(new TextEncoder().encode('x'), recipient, context);
  assert.notEqual(a.ephemeralPublicKey, b.ephemeralPublicKey);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test('a malformed recipient key is refused rather than guessed at', () => {
  for (const bad of ['', '0x1234', 'z'.repeat(64)]) {
    assert.throws(() => parseRecipientKey(bad), SealError, bad);
  }
});

// — the handler —

function authorizationFor(
  recipientPublicKey: string,
  overrides: Partial<ExportAuthorization> = {},
): ExportAuthorization {
  return {
    licenseId: 42n,
    instanceId: toBytes32(INSTANCE_ID),
    recipientPublicKey: `0x${recipientPublicKey}` as Hex,
    nonce: 1n,
    expiry: 1_600n,  // now (1_000) + 600s, inside MAX_AUTHORIZATION_LIFETIME_SECONDS
    ...overrides,
  };
}

async function run(options: {
  authorization: ExportAuthorization;
  signature?: Hex;
  signer?: Address;
  balance?: bigint;
  code?: Hex;
  now?: bigint;
}) {
  const signature =
    options.signature ??
    (await HOLDER.signTypedData({
      domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
      types: EXPORT_AUTHORIZATION_TYPES,
      primaryType: 'ExportAuthorization',
      message: options.authorization,
    }));

  const store = new JsonStore(await mkdtemp(join(tmpdir(), 'verity-export-')));
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 2,
    data: {profiles: [{id: 'a', givenName: 'Ada', familyName: 'Lovelace'}]},
  });

  return exportState(
    {authorization: options.authorization, signature, signer: options.signer ?? HOLDER.address},
    {
      config: CONFIG,
      client: fakeClient({
        balance: options.balance ?? 1n,
        ...(options.code === undefined ? {} : {code: options.code}),
      }),
      guestAgent: fakeGuestAgent(),
      store,
      now: () => options.now ?? 1_000n,
    },
  );
}

test('an authorized holder gets a bundle they can open', async () => {
  const {publicKeyHex, privateKey} = generateRecipientKeypair();
  const authorization = authorizationFor(publicKeyHex);
  const result = await run({authorization});

  assert.equal(result.status, 'complete');
  assert.ok(result.bundle);

  const plaintext = open(result.bundle, privateKey, {
    licenseId: authorization.licenseId,
    instanceId: INSTANCE_ID,
  }).toString('utf8');
  assert.match(plaintext, /Lovelace/);
});

/** A previous holder exporting an instance they sold is a data breach with a valid signature on it. */
test('a previous holder cannot export', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const result = await run({authorization: authorizationFor(publicKeyHex), balance: 0n});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /holder check failed/);
  assert.equal(result.bundle, undefined);
});

test('a signature from someone else is refused', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const authorization = authorizationFor(publicKeyHex);
  const signature = await STRANGER.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: EXPORT_AUTHORIZATION_TYPES,
    primaryType: 'ExportAuthorization',
    message: authorization,
  });
  const result = await run({authorization, signature});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /signature rejected/);
});

test('an expired authorization is refused', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const result = await run({
    authorization: authorizationFor(publicKeyHex, {expiry: 500n}),
    now: 501n,
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /expired/);
});

test('an authorization for another instance is refused', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const result = await run({
    authorization: authorizationFor(publicKeyHex, {instanceId: toBytes32('0x01')}),
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /instanceId/);
});

test('a contract signer is refused as unsupported', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const result = await run({authorization: authorizationFor(publicKeyHex), code: '0x6000'});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /not implemented in MVP/);
});

/**
 * The two authorizations must not be interchangeable. `LicenseToken.mint` and `upgrade` shared a
 * struct once, and it made every check in one of them decorative.
 */
test('a migration signature does not authorize an export', async () => {
  const {publicKeyHex} = generateRecipientKeypair();
  const authorization = authorizationFor(publicKeyHex);

  // Same field values, signed under the migration type.
  const migrationShaped = await HOLDER.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: MIGRATION_AUTHORIZATION_TYPES,
    primaryType: 'MigrationAuthorization',
    message: {
      licenseId: authorization.licenseId,
      fromDigest: authorization.recipientPublicKey,
      toDigest: authorization.recipientPublicKey,
      instanceId: authorization.instanceId,
      nonce: authorization.nonce,
      expiry: authorization.expiry,
    },
  });

  const result = await run({authorization, signature: migrationShaped});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /signature rejected/);
});

/** The recipient key is signed, so a relayer cannot redirect the bundle to themselves. */
test('changing the recipient key invalidates the signature', async () => {
  const mine = generateRecipientKeypair();
  const theirs = generateRecipientKeypair();
  const signed = authorizationFor(mine.publicKeyHex);
  const signature = await HOLDER.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: EXPORT_AUTHORIZATION_TYPES,
    primaryType: 'ExportAuthorization',
    message: signed,
  });

  const redirected = {...signed, recipientPublicKey: `0x${theirs.publicKeyHex}` as Hex};
  const result = await run({authorization: redirected, signature});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /signature rejected/);
});
