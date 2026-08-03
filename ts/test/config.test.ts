/**
 * Configuration, which is a security boundary rather than plumbing.
 *
 * Every value here comes from `app-compose.json`, and that document is what `composeHash` hashes and
 * `MR-CONFIG-ID` measures. So a holder verifying this app before use is also verifying **which RPC
 * endpoint it will trust** and **which LicenseToken it will believe** — the two things that decide
 * who it thinks the holder is.
 *
 * The module never appeared in the coverage report, because nothing imported it.
 */

import assert from 'node:assert/strict';
import {test} from 'node:test';

import {ConfigError, loadConfig} from '../src/config.ts';

const VALID = {
  VERITY_CHAIN_ID: '84532',
  VERITY_RPC_URL: 'https://sepolia.base.org',
  VERITY_LICENSE_TOKEN: '0x1111111111111111111111111111111111111111',
  VERITY_APP_MANIFEST: '0x2222222222222222222222222222222222222222',
  VERITY_VERSION: '1.0.0',
};

test('a complete configuration loads', () => {
  const config = loadConfig(VALID);
  assert.equal(config.chainId, 84532);
  assert.equal(config.rpcUrl, 'https://sepolia.base.org');
  assert.equal(config.version, '1.0.0');
});

test('addresses are checksummed on the way in', () => {
  const config = loadConfig({...VALID, VERITY_LICENSE_TOKEN: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd'});
  // Normalising here means a comparison later cannot fail on case alone.
  assert.notEqual(config.licenseToken, '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd');
  assert.equal(config.licenseToken.toLowerCase(), '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd');
});

/**
 * Defaults to true because that is what the platform defaults to. A template that assumed the safer
 * value would teach developers to expect privacy they do not have.
 */
test('publicLogs defaults to true and only the exact string "false" disables it', () => {
  assert.equal(loadConfig(VALID).publicLogs, true);
  assert.equal(loadConfig({...VALID, VERITY_PUBLIC_LOGS: 'false'}).publicLogs, false);
  assert.equal(loadConfig({...VALID, VERITY_PUBLIC_LOGS: 'FALSE'}).publicLogs, true);
  assert.equal(loadConfig({...VALID, VERITY_PUBLIC_LOGS: '0'}).publicLogs, true);
});

// — every required value is required —

for (const key of Object.keys(VALID)) {
  test(`${key} missing is refused`, () => {
    const incomplete = {...VALID};
    delete (incomplete as Record<string, string>)[key];
    assert.throws(() => loadConfig(incomplete), ConfigError);
  });

  test(`${key} empty is refused`, () => {
    assert.throws(() => loadConfig({...VALID, [key]: '   '}), ConfigError);
  });
}

/** The error has to say *where* to fix it: these values live in the measured compose, not in a
 * deployment setting someone can flip. */
test('the error explains that the value belongs in app-compose.json', () => {
  assert.throws(
    () => loadConfig({...VALID, VERITY_RPC_URL: ''}),
    (err: ConfigError) => /app-compose\.json/.test(err.message) && /composeHash/.test(err.message),
  );
});

// — malformed values —

test('a non-address is refused rather than used', () => {
  for (const bad of ['not-an-address', '0x123', '1111111111111111111111111111111111111111']) {
    assert.throws(() => loadConfig({...VALID, VERITY_LICENSE_TOKEN: bad}), ConfigError, bad);
  }
});

test('a non-numeric or non-positive chain id is refused', () => {
  for (const bad of ['mainnet', '0', '-1', '1.5', '']) {
    assert.throws(() => loadConfig({...VALID, VERITY_CHAIN_ID: bad}), ConfigError, bad);
  }
});

test('a malformed URL is refused', () => {
  for (const bad of ['not a url', 'sepolia.base.org', '://missing-scheme']) {
    assert.throws(() => loadConfig({...VALID, VERITY_RPC_URL: bad}), ConfigError, bad);
  }
});

/**
 * The RPC endpoint is the sole source of the holder-identity decision. Over a scheme this app does
 * not understand, that decision has no defined source at all.
 */
test('a non-HTTP scheme is refused', () => {
  for (const bad of ['ws://sepolia.base.org', 'file:///etc/passwd', 'ftp://example.com']) {
    assert.throws(() => loadConfig({...VALID, VERITY_RPC_URL: bad}), ConfigError, bad);
  }
});

test('plain http is accepted, which is a deliberate gap worth knowing about', () => {
  // Documented rather than asserted as good: a network-position attacker can forge `balanceOf` over
  // plaintext, and being pinned in the compose makes that choice *visible*, not *safe*. Tightening
  // this to localhost-only is tracked in the test plan.
  assert.doesNotThrow(() => loadConfig({...VALID, VERITY_RPC_URL: 'http://127.0.0.1:8545'}));
});
