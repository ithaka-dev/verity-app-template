import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {EXIT, main} from '../src/compose-check-cli.ts';

const PINNED = 'sha256:' + 'ab'.repeat(32);

/** Collects `main`'s output without touching `process`, so every branch is testable in-process. */
function recorder(): {
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  readonly outLines: string[];
  readonly errLines: string[];
} {
  const outLines: string[] = [];
  const errLines: string[] = [];
  return {out: (line) => outLines.push(line), err: (line) => errLines.push(line), outLines, errLines};
}

function writeCompose(dir: string, name: string, inner: string): string {
  const path = join(dir, name);
  writeFileSync(path, JSON.stringify({docker_compose_file: inner}));
  return path;
}

/** L-05 step 2's exact fixture shape (`printf` over a tag-referenced image). */
function taggedCompose(dir: string): string {
  return writeCompose(dir, 'tagged.json', 'services:\n  app:\n    image: ghcr.io/x/y:main\n');
}

/** L-05 step 3's exact fixture shape (`printf` over a digest-pinned image). */
function pinnedCompose(dir: string): string {
  return writeCompose(dir, 'pinned.json', `services:\n  app:\n    image: ghcr.io/x/y@${PINNED}\n`);
}

test("L-05 step 2's fixture: a tagged image is refused, and stdout stays empty", () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const io = recorder();
    const code = main([taggedCompose(dir)], io);
    assert.equal(code, EXIT.refused);
    assert.deepEqual(io.outLines, []);
    assert.ok(io.errLines.some((line) => line.includes('not-pinned')));
    assert.ok(io.errLines.some((line) => line.includes('by tag, not digest')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test("L-05 step 3's fixture: a digest-pinned image is accepted", () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const io = recorder();
    const code = main([pinnedCompose(dir)], io);
    assert.equal(code, EXIT.ok);
    assert.ok(io.outLines.some((line) => line.includes('app') && line.includes(PINNED)));
    assert.ok(io.outLines.some((line) => line.includes('composeHash')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('one argument: success output states the cross-check did NOT run', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const io = recorder();
    const code = main([pinnedCompose(dir)], io);
    assert.equal(code, EXIT.ok);
    assert.ok(io.outLines.some((line) => line.includes('note') && line.includes('NOT checked')));
    assert.ok(!io.outLines.some((line) => line.includes('cross-checked')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('two arguments, matching digest: success output states the cross-check ran', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const path = pinnedCompose(dir);
    // The uppercase form makes `line.includes(PINNED)` (lowercase) a genuine test of the display
    // helper's normalisation, not just of the case-insensitive comparison it sits on top of.
    for (const form of [
      PINNED,
      PINNED.replace('sha256:', ''),
      `0x${PINNED.replace('sha256:', '')}`,
      `sha256:${PINNED.replace('sha256:', '').toUpperCase()}`,
    ]) {
      const io = recorder();
      const code = main([path, form], io);
      assert.equal(code, EXIT.ok, form);
      assert.ok(
        io.outLines.some((line) => line.includes('cross-checked') && line.includes(PINNED)),
        form,
      );
    }
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('two arguments, a digest the compose does not reference: refused as digest-absent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const path = pinnedCompose(dir);
    const io = recorder();
    const code = main([path, `sha256:${'11'.repeat(32)}`], io);
    assert.equal(code, EXIT.refused);
    assert.deepEqual(io.outLines, []);
    assert.ok(io.errLines.some((line) => line.includes('digest-absent')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('a compose with no images is refused as no-images', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const path = writeCompose(dir, 'no-images.json', 'services:\n  app:\n    build: .\n');
    const io = recorder();
    assert.equal(main([path], io), EXIT.refused);
    assert.ok(io.errLines.some((line) => line.includes('no-images')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('a document that is not JSON is refused as not-json', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const path = join(dir, 'not-json.json');
    writeFileSync(path, 'not json');
    const io = recorder();
    assert.equal(main([path], io), EXIT.refused);
    assert.ok(io.errLines.some((line) => line.includes('not-json')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('a document with no `docker_compose_file` string is refused as no-compose-file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const path = join(dir, 'empty.json');
    writeFileSync(path, '{}');
    const io = recorder();
    assert.equal(main([path], io), EXIT.refused);
    assert.ok(io.errLines.some((line) => line.includes('no-compose-file')));
  } finally {
    rmSync(dir, {recursive: true});
  }
});

test('zero arguments: unusable, with a usage message', () => {
  const io = recorder();
  assert.equal(main([], io), EXIT.unusable);
  assert.deepEqual(io.outLines, []);
  assert.ok(io.errLines.some((line) => line.includes('usage')));
});

test('three arguments: unusable, not silently ignoring the extra', () => {
  const io = recorder();
  assert.equal(main(['a', 'b', 'c'], io), EXIT.unusable);
  assert.ok(io.errLines.some((line) => line.includes('usage')));
});

test('a nonexistent path is unusable, and stdout stays empty', () => {
  const io = recorder();
  const code = main([join(tmpdir(), 'check-compose-does-not-exist', 'x.json')], io);
  assert.equal(code, EXIT.unusable);
  assert.deepEqual(io.outLines, []);
  assert.ok(io.errLines.some((line) => line.includes('cannot read')));
});

test('a directory given as the path is unusable', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const io = recorder();
    const code = main([dir], io);
    assert.equal(code, EXIT.unusable);
    assert.deepEqual(io.outLines, []);
  } finally {
    rmSync(dir, {recursive: true});
  }
});

/**
 * The exit codes are the contract with L-05 and with every copied pipeline. A future renumbering
 * should fail this test rather than silently change what a shell script three repos away concludes.
 */
test('EXIT is literally {ok: 0, refused: 1, unusable: 2}', () => {
  assert.deepEqual(EXIT, {ok: 0, refused: 1, unusable: 2});
});

/**
 * Spawned, over the real entry file — the only thing that covers what `main` structurally cannot
 * see: that `scripts/check-compose.ts` exists at the path L-05 hardcodes, that it loads under
 * `--experimental-strip-types`, that `process.argv.slice(2)` is the right slice, that
 * `process.exitCode` actually reaches the shell, and that stderr is stderr.
 *
 * Both spawns isolate the child's own coverage collection. Without this, the child inherits
 * `NODE_V8_COVERAGE` from the parent test run and writes its own coverage into the same directory,
 * racing the parent's report flush — measured to flip this module's reported branch coverage
 * between runs of the identical, all-passing suite. Deleting this line does not break any
 * assertion below; it reintroduces a coverage floor that fails on scheduling, not on merit.
 */
test('spawned: the real entry file at the path L-05 hardcodes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'check-compose-'));
  try {
    const tagged = taggedCompose(dir);
    const pinned = pinnedCompose(dir);
    const entry = fileURLToPath(new URL('../scripts/check-compose.ts', import.meta.url));
    const isolatedEnv = {...process.env, NODE_V8_COVERAGE: ''};

    const refused = spawnSync(process.execPath, ['--experimental-strip-types', entry, tagged], {
      encoding: 'utf8',
      env: isolatedEnv,
    });
    assert.equal(refused.status, EXIT.refused);
    assert.equal(refused.stdout, '');
    // Containment, not equality: CI's Node 22 writes an ExperimentalWarning to stderr that local
    // Node does not, so an exact match would pass on every developer machine and fail only in CI.
    assert.ok(refused.stderr.includes('not-pinned'));
    // A load failure (a syntax error, a strip-types rejection) also exits non-zero with a stack
    // trace, which would otherwise read as an indistinguishable "successful" refusal.
    assert.ok(!refused.stderr.includes(' at '));

    const accepted = spawnSync(process.execPath, ['--experimental-strip-types', entry, pinned], {
      encoding: 'utf8',
      env: isolatedEnv,
    });
    assert.equal(accepted.status, EXIT.ok);
    assert.ok(accepted.stdout.includes('app'));
    assert.ok(!accepted.stderr.includes(' at '));
  } finally {
    rmSync(dir, {recursive: true});
  }
});
