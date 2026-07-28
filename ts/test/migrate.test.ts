import assert from 'node:assert/strict';
import {mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';

import type {Address, Hex, PublicClient} from 'viem';
import {privateKeyToAccount} from 'viem/accounts';

import {
  MIGRATION_AUTHORIZATION_TYPES,
  migrationDomain,
  type MigrationAuthorization,
} from '../src/authorization.ts';
import type {AppConfig} from '../src/config.ts';
import type {GuestAgent} from '../src/guest-agent.ts';
import {migrate, toBytes32} from '../src/handlers/migrate.ts';
import {recordBootComposeHash} from '../src/state/boot-record.ts';
import {PROFILES_DOCUMENT} from '../src/state/migrations.ts';
import {JsonStore} from '../src/state/store.ts';

const HOLDER = privateKeyToAccount(`0x${'11'.repeat(32)}`);
const STRANGER = privateKeyToAccount(`0x${'22'.repeat(32)}`);

const CONFIG: AppConfig = {
  chainId: 84532,
  rpcUrl: 'https://example.invalid',
  licenseToken: '0x1111111111111111111111111111111111111111',
  appManifest: '0x2222222222222222222222222222222222222222',
  version: '2.0.0',
  publicLogs: true,
};

const RUNNING_COMPOSE = `0x${'ab'.repeat(32)}` as Hex;
const PREVIOUS_COMPOSE = `0x${'cd'.repeat(32)}` as Hex;
const INSTANCE_ID = '0x00000000000000000000000000000000000000000000000000000000000000ff';

/** Only the two methods the handler uses; anything else would be an untested code path anyway. */
function fakeGuestAgent(overrides: Partial<{composeHash: string}> = {}): GuestAgent {
  return {
    info: async () => ({
      appId: '0xapp',
      instanceId: INSTANCE_ID,
      composeHash: overrides.composeHash ?? RUNNING_COMPOSE,
    }),
  } as unknown as GuestAgent;
}

/** `getCode` decides EOA vs contract; `readContract` answers `balanceOf`. */
function fakeClient(options: {balance: bigint; code?: Hex}): PublicClient {
  return {
    getCode: async () => options.code,
    readContract: async () => options.balance,
  } as unknown as PublicClient;
}

async function freshStore(): Promise<JsonStore> {
  return new JsonStore(await mkdtemp(join(tmpdir(), 'verity-migrate-')));
}

function authorizationFor(overrides: Partial<MigrationAuthorization> = {}): MigrationAuthorization {
  return {
    licenseId: 4242n, // a licence id, not a version id — see ADR 0023
    fromDigest: PREVIOUS_COMPOSE,
    toDigest: RUNNING_COMPOSE,
    instanceId: toBytes32(INSTANCE_ID),
    nonce: 1n,
    expiry: 1_600n,  // now (1_000) + 600s, inside MAX_AUTHORIZATION_LIFETIME_SECONDS
    ...overrides,
  };
}

async function sign(
  authorization: MigrationAuthorization,
  account = HOLDER,
): Promise<Hex> {
  return account.signTypedData({
    domain: migrationDomain(CONFIG.chainId, CONFIG.licenseToken),
    types: MIGRATION_AUTHORIZATION_TYPES,
    primaryType: 'MigrationAuthorization',
    message: authorization,
  });
}

async function run(options: {
  authorization?: MigrationAuthorization;
  signature?: Hex;
  signer?: Address;
  balance?: bigint;
  code?: Hex;
  composeHash?: string;
  store?: JsonStore;
  now?: bigint;
  recordPreviousBoot?: boolean;
}) {
  const authorization = options.authorization ?? authorizationFor();
  const store = options.store ?? (await freshStore());
  if (options.recordPreviousBoot !== false) {
    await recordBootComposeHash(store, PREVIOUS_COMPOSE);
  }
  return {
    store,
    result: await migrate(
      {
        authorization,
        signature: options.signature ?? (await sign(authorization)),
        signer: options.signer ?? HOLDER.address,
      },
      {
        config: CONFIG,
        client: fakeClient({
          balance: options.balance ?? 1n,
          ...(options.code === undefined ? {} : {code: options.code}),
        }),
        guestAgent: fakeGuestAgent(
          options.composeHash === undefined ? {} : {composeHash: options.composeHash},
        ),
        store,
        now: () => options.now ?? 1_000n,
      },
    ),
  };
}

test('a valid authorization migrates', async () => {
  const store = await freshStore();
  await store.write(PROFILES_DOCUMENT, {
    schemaVersion: 1,
    data: {profiles: [{id: 'a', name: 'Ada Lovelace'}]},
  });

  const {result} = await run({store});
  assert.equal(result.status, 'complete');
  assert.equal(result.idempotentReplay, false);
});

/** The platform may retry. A replayed authorization must be recognised, not re-executed. */
test('replaying the same authorization short-circuits', async () => {
  const store = await freshStore();
  const authorization = authorizationFor();

  const first = await run({store, authorization});
  assert.equal(first.result.idempotentReplay, false);

  const second = await run({store, authorization});
  assert.equal(second.result.status, 'complete');
  assert.equal(second.result.idempotentReplay, true);
});

test('an expired authorization is refused', async () => {
  const {result} = await run({
    authorization: authorizationFor({expiry: 500n}),
    now: 501n,
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /expired/);
});

/**
 * The attack `instanceId` exists to stop: a genuine signature, from the real holder, for a
 * different instance they own. A signature check alone would accept it.
 */
test('an authorization for another instance is refused', async () => {
  const {result} = await run({
    authorization: authorizationFor({instanceId: toBytes32('0x01')}),
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /instanceId/);
});

test('an authorization naming a different target version is refused', async () => {
  const {result} = await run({
    authorization: authorizationFor({toDigest: `0x${'ee'.repeat(32)}`}),
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /toDigest/);
});

test('an authorization naming the wrong source version is refused', async () => {
  const {result} = await run({
    authorization: authorizationFor({fromDigest: `0x${'ee'.repeat(32)}`}),
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /fromDigest/);
});

test('a signature from someone other than the claimed signer is refused', async () => {
  const authorization = authorizationFor();
  const {result} = await run({
    authorization,
    signature: await sign(authorization, STRANGER),
  });
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /signature rejected/);
});

/**
 * The case that makes chain resolution mandatory. The signature is genuine and the authorization
 * is well-formed — the signer simply does not hold the licence any more, which is what selling it
 * looks like from the app's side.
 */
test('a previous holder cannot authorize a migration', async () => {
  const {result} = await run({balance: 0n});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /holder check failed/);
});

test('a contract signer is refused as unsupported, not as a bad signature', async () => {
  const {result} = await run({code: '0x60006000'});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /not implemented in MVP/);
});

/**
 * Without a compose hash from the platform there is nothing to check `toDigest` against, and the
 * check would degrade to comparing the message with itself.
 */
test('refuses to migrate when the platform reports no compose hash', async () => {
  const {result} = await run({composeHash: ''});
  assert.equal(result.status, 'failed');
  assert.match(result.detail, /compose hash/);
});

/** A first boot has no recorded previous hash, and must still be able to migrate. */
test('a first boot with no recorded previous hash still migrates', async () => {
  const {result} = await run({recordPreviousBoot: false});
  assert.equal(result.status, 'complete');
});

/** Nothing is written before the checks pass. */
test('a rejected authorization leaves no journal entry', async () => {
  const store = await freshStore();
  await run({store, balance: 0n});
  const journal = await store.read(`migration-journal`);
  assert.equal(journal, undefined);
});
