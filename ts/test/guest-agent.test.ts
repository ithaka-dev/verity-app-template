/**
 * The dStack guest agent client.
 *
 * Untested until now, and it carries this repo's **first hard rule**: the guest agent answers on
 * `tappd.sock`, and `dstack.sock` returns 404 for every method on 0.5.7 despite appearing in
 * current documentation. That fact came from an experiment, lives in one module, and ships in a
 * template that gets copied — so a regression here breaks every app built on it, at the moment they
 * try to obtain their own keys.
 *
 * It never appeared in the coverage report at all, because nothing imported it.
 *
 * These tests run against a real Unix socket rather than a mocked `http.request`. Mocking the
 * transport would leave the one thing worth checking — that the client talks to the right socket,
 * in the right shape — asserted against a fiction.
 */

import assert from 'node:assert/strict';
import {createServer, type Server} from 'node:http';
import {mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {after, test} from 'node:test';

import {GuestAgent, GuestAgentError} from '../src/guest-agent.ts';

interface Route {
  status?: number;
  body: string;
  delayMs?: number;
}

const servers: Server[] = [];

after(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
});

/** A guest agent on a real Unix socket, answering only the paths it is given. */
async function fakeAgent(routes: Record<string, Route>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'verity-agent-'));
  const socketPath = join(dir, 'tappd.sock');

  const server = createServer((req, res) => {
    const route = routes[req.url ?? ''];
    if (route === undefined) {
      // What `dstack.sock` does on 0.5.7 for every method — the fact this module encodes.
      res.writeHead(404).end('not found');
      return;
    }
    const send = () => res.writeHead(route.status ?? 200).end(route.body);
    if (route.delayMs === undefined) send();
    else setTimeout(send, route.delayMs);
  });

  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  servers.push(server);
  return socketPath;
}

const INFO = JSON.stringify({
  app_id: '465357ad5bfd16ef62f2c6a49204fe79affcfd05',
  instance_id: 'e3f2a1b0c9d8e7f60514233241506978a9bacbdc',
  compose_hash: '4cdefa0e0029af12f25a95687b9bf72ea75f623d3dbfc801265fbd9f0c993e28',
});

// — identity —

test('reads app_id, instance_id and compose_hash from /prpc/Info', async () => {
  const socketPath = await fakeAgent({'/prpc/Info': {body: INFO}});
  const info = await new GuestAgent({socketPath}).info();

  assert.equal(info.appId, '465357ad5bfd16ef62f2c6a49204fe79affcfd05');
  assert.equal(info.instanceId, 'e3f2a1b0c9d8e7f60514233241506978a9bacbdc');
  assert.equal(info.composeHash.length, 64);
});

/** Present under different spellings across versions. Absent is not fatal for `health`. */
test('accepts app_compose_hash as an alternate spelling', async () => {
  const socketPath = await fakeAgent({
    '/prpc/Info': {body: JSON.stringify({app_id: 'a', instance_id: 'b', app_compose_hash: 'cc'})},
  });
  assert.equal((await new GuestAgent({socketPath}).info()).composeHash, 'cc');
});

/**
 * Degrades rather than throws, because liveness does not depend on it — but `migrate` refuses when
 * it is empty, since it has nothing to compare `toDigest` against.
 */
test('a missing compose hash degrades to empty rather than failing', async () => {
  const socketPath = await fakeAgent({
    '/prpc/Info': {body: JSON.stringify({app_id: 'a', instance_id: 'b'})},
  });
  assert.equal((await new GuestAgent({socketPath}).info()).composeHash, '');
});

test('a response missing app_id is refused, not silently accepted', async () => {
  const socketPath = await fakeAgent({
    '/prpc/Info': {body: JSON.stringify({instance_id: 'b'})},
  });
  await assert.rejects(() => new GuestAgent({socketPath}).info(), GuestAgentError);
});

test('an empty app_id is refused — it would compare equal to another empty one', async () => {
  const socketPath = await fakeAgent({
    '/prpc/Info': {body: JSON.stringify({app_id: '', instance_id: 'b'})},
  });
  await assert.rejects(() => new GuestAgent({socketPath}).info(), GuestAgentError);
});

// — the hard rule —

/**
 * **The rule this module exists to encode.** A 404 from the guest agent almost always means the
 * wrong socket, and the error must carry the status so that is diagnosable rather than mysterious.
 */
test('a 404 carries the status, because it almost always means the wrong socket', async () => {
  const socketPath = await fakeAgent({});
  await assert.rejects(
    () => new GuestAgent({socketPath}).info(),
    (err: GuestAgentError) => err.status === 404 && err.method === 'Info',
  );
});

test('a 500 is distinguishable from a 404', async () => {
  const socketPath = await fakeAgent({'/prpc/Info': {status: 500, body: 'boom'}});
  await assert.rejects(
    () => new GuestAgent({socketPath}).info(),
    (err: GuestAgentError) => err.status === 500,
  );
});

test('a malformed body surfaces as an error rather than undefined fields', async () => {
  const socketPath = await fakeAgent({'/prpc/Info': {body: 'not json'}});
  await assert.rejects(() => new GuestAgent({socketPath}).info());
});

// — timeouts —

/**
 * Explicit, not left to Node's default of none. An agent that accepts a connection and then stalls
 * would hang a health check forever, and "forever" is indistinguishable from "unhealthy" only after
 * somebody notices.
 */
test('a stalled agent times out rather than hanging', async () => {
  const socketPath = await fakeAgent({'/prpc/Info': {body: INFO, delayMs: 2_000}});
  const started = Date.now();
  await assert.rejects(
    () => new GuestAgent({socketPath, timeoutMs: 150}).info(),
    (err: GuestAgentError) => err.status === undefined && /timed out/.test(err.message),
  );
  assert.ok(Date.now() - started < 1_500, 'must not wait for the slow response');
});

test('an unreachable socket fails with a transport error', async () => {
  await assert.rejects(
    () => new GuestAgent({socketPath: '/nonexistent/tappd.sock'}).info(),
    (err: GuestAgentError) => err.status === undefined,
  );
});

// — key derivation —

test('derives a key and returns the PEM with its certificate chain', async () => {
  const key = '-----BEGIN EC PRIVATE KEY-----\nMHcCAQ\n-----END EC PRIVATE KEY-----';
  const socketPath = await fakeAgent({
    '/prpc/DeriveKey': {body: JSON.stringify({key, certificate_chain: ['cert-a', 'cert-b']})},
  });
  const derived = await new GuestAgent({socketPath}).deriveKey('some/path');

  assert.equal(derived.privateKeyPem, key);
  assert.deepEqual(derived.certificateChain, ['cert-a', 'cert-b']);
});

/**
 * **The leak this template exists to prevent.** A derived key was printed into public logs during
 * the experiment that produced this guidance, by someone who had already designed the final test to
 * avoid exactly that. `public_logs` defaults to true.
 */
test('deriving a key never prints the key', async () => {
  const key = `-----BEGIN EC PRIVATE KEY-----\n${'A'.repeat(64)}\n-----END EC PRIVATE KEY-----`;
  const socketPath = await fakeAgent({
    '/prpc/DeriveKey': {body: JSON.stringify({key, certificate_chain: []})},
  });

  const lines: string[] = [];
  const original = console.log;
  console.log = (line: string) => lines.push(line);
  try {
    await new GuestAgent({socketPath}).deriveKey('probe');
  } finally {
    console.log = original;
  }

  assert.ok(lines.length > 0, 'it should log that a key was derived');
  const emitted = lines.join('\n');
  assert.ok(!emitted.includes(key), 'the key must never appear');
  assert.ok(!emitted.includes('BEGIN EC PRIVATE KEY'), 'nor any part of it');
  assert.match(emitted, /"key_fp":"[0-9a-f]{16}"/, 'a fingerprint, so continuity stays checkable');
});

test('a missing key in the response is refused', async () => {
  const socketPath = await fakeAgent({
    '/prpc/DeriveKey': {body: JSON.stringify({certificate_chain: []})},
  });
  await assert.rejects(() => new GuestAgent({socketPath}).deriveKey('p'), GuestAgentError);
});

test('a non-array certificate chain degrades to empty rather than throwing', async () => {
  const socketPath = await fakeAgent({
    '/prpc/DeriveKey': {body: JSON.stringify({key: 'k', certificate_chain: 'nope'})},
  });
  assert.deepEqual((await new GuestAgent({socketPath}).deriveKey('p')).certificateChain, []);
});

// — quotes —

/**
 * Returned raw. A verifier must parse the quote itself, because Intel's signature covers the quote
 * and not anyone's summary of it.
 */
test('returns the quote raw', async () => {
  const socketPath = await fakeAgent({
    '/prpc/TdxQuote': {body: JSON.stringify({quote: '0400020081000000'})},
  });
  const quote = await new GuestAgent({socketPath}).tdxQuote(new Uint8Array([1, 2, 3]));
  assert.equal(quote, '0400020081000000');
});

test('a missing quote is refused', async () => {
  const socketPath = await fakeAgent({'/prpc/TdxQuote': {body: '{}'}});
  await assert.rejects(
    () => new GuestAgent({socketPath}).tdxQuote(new Uint8Array()),
    GuestAgentError,
  );
});
