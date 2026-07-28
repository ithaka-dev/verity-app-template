import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {fileURLToPath} from 'node:url';

import type {Address} from 'viem';

import {tokenIdFor} from '../src/holder.ts';

interface Vector {
  readonly appManifest: Address;
  readonly version: string;
  readonly tokenId: string;
}

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../test-vectors/token-id.json', import.meta.url)), 'utf8'),
) as {vectors: readonly Vector[]};

test('tokenIdFor matches the Solidity vectors', () => {
  assert.ok(vectors.vectors.length > 0, 'vector file must not be empty');
  for (const vector of vectors.vectors) {
    assert.equal(
      tokenIdFor(vector.appManifest, vector.version),
      BigInt(vector.tokenId),
      `${vector.appManifest} @ ${JSON.stringify(vector.version)}`,
    );
  }
});

test('tokenIdFor separates apps and versions', () => {
  const a = '0x1111111111111111111111111111111111111111' as Address;
  const b = '0x2222222222222222222222222222222222222222' as Address;
  assert.notEqual(tokenIdFor(a, '1.0.0'), tokenIdFor(a, '1.0.1'));
  assert.notEqual(tokenIdFor(a, '1.0.0'), tokenIdFor(b, '1.0.0'));
});

test('version strings that concatenate alike do not collide', () => {
  // The reason the contract uses abi.encode rather than encodePacked. A collision here would let
  // one app's licence entitle a holder to run another's.
  const a = '0x1111111111111111111111111111111111111111' as Address;
  assert.notEqual(tokenIdFor(a, '1.0'), tokenIdFor(a, '10'));
});
