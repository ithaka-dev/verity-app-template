/**
 * Logging that cannot leak a secret, because the only way to log one is to fingerprint it.
 *
 * ## Why this module exists
 *
 * `app-compose.json` sets `public_logs` — and it commonly defaults to **`true`**, which means
 * container stdout is retrievable by anyone who can reach the CVM's log endpoint. A key printed
 * here is a key published.
 *
 * That is not a hypothetical failure. During the experiment that produced this guidance, a
 * KMS-derived private key was printed into public logs by someone who had *already designed the
 * final test to avoid exactly that* — the leak happened in an earlier discovery run, where the
 * value was "just being checked." Knowing the rule is demonstrably not enough. So the template
 * makes the safe thing the only thing that is convenient.
 *
 * ## The pattern
 *
 * Never print a secret. Print `fingerprint(domain, secret)` — a domain-separated SHA-256 prefix.
 * Two fingerprints are comparable (did the key survive the upgrade?) without either revealing
 * anything about the value.
 *
 * **Domain separation is not decoration.** Without it, a fingerprint computed over a migration
 * nonce and one computed over a signing key are the same function of the same bytes, so a value
 * logged in a harmless context confirms a guess about a value in a sensitive one. The domain makes
 * each fingerprint useless outside the place it was taken.
 */

import {createHash} from 'node:crypto';

/**
 * Domains are enumerated rather than free-form strings.
 *
 * A caller who can pass any domain will eventually pass the same one twice for different kinds of
 * secret, which quietly undoes the separation above. Adding a domain should be a deliberate edit,
 * visible in review.
 */
export type FingerprintDomain =
  | 'derived-key' // a key obtained from the guest agent
  | 'holder-signature' // a holder's EIP-712 signature
  | 'migration-nonce'
  | 'export-key' // the holder public key an export is encrypted to
  | 'instance-secret'; // anything else the enclave holds and must not print

/**
 * A short, domain-separated digest of a secret.
 *
 * Comparable across time and across instances; not reversible, and not comparable across domains.
 *
 * Truncated to 16 hex characters (64 bits). Enough that an accidental collision between two
 * different keys is not a thing that happens, and short enough to read in a log line — the full
 * digest would be treated as noise and skipped, which is its own kind of failure.
 */
const DOMAINS: ReadonlySet<string> = new Set<FingerprintDomain>([
  'derived-key',
  'holder-signature',
  'migration-nonce',
  'export-key',
  'instance-secret',
]);

export function fingerprint(domain: FingerprintDomain, secret: string | Uint8Array): string {
  // Checked at runtime, not only in the type system. Without this a caller reaching the function
  // from untyped code could pass `'derived-key|x'` and collide with `fingerprint('derived-key',
  // 'x|y')` — which is exactly the separation the separator is supposed to provide. The comment
  // below claimed no such pair existed; it was true of the type and false of the runtime.
  if (!DOMAINS.has(domain)) {
    throw new TypeError(`unknown fingerprint domain ${domain}; domains are a closed set`);
  }
  const hash = createHash('sha256');
  // The separator cannot appear in a domain because domains are a closed set, so there is no
  // (domain, secret) pair that hashes the same as a different (domain, secret) pair.
  hash.update(`verity-fp|${domain}|`, 'utf8');
  hash.update(typeof secret === 'string' ? Buffer.from(secret, 'utf8') : secret);
  return hash.digest('hex').slice(0, 16);
}

/**
 * Content shapes that are unambiguously secret wherever they appear.
 *
 * Deliberately **not** including bare 64-character hex. A `bytes32` is that shape, and so is a
 * private key — the string alone cannot distinguish them. Refusing all of them would block compose
 * hashes, instance ids and digests, which are public values an operational log genuinely needs, and
 * a checker that fires on ordinary data is a checker someone removes. Field names carry that
 * distinction instead; see `SUSPICIOUS_FIELD`.
 */
const SECRET_SHAPES: ReadonlyArray<{name: string; pattern: RegExp}> = [
  {name: 'PEM private key', pattern: /-----BEGIN[A-Z ]*PRIVATE KEY-----/},
  {name: 'JWT', pattern: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./},
  {name: 'mnemonic-like phrase', pattern: /\b(?:[a-z]{3,8}\s+){11,}[a-z]{3,8}\b/},
];

/**
 * Field names that should never carry a raw value.
 *
 * The `_fp` suffix is the sanctioned escape, and it is the only one: `key_fp` is a fingerprint and
 * passes, `key` does not. That asymmetry is the whole mechanism — the safe spelling is one
 * character longer than the unsafe one, and the unsafe one fails in a test.
 */
const SUSPICIOUS_WORDS: ReadonlySet<string> = new Set([
  'key',
  'keys',
  'secret',
  'private',
  'privkey',
  'apikey',
  'passphrase',
  'password',
  'credential',
  'credentials',
  'seed',
  'mnemonic',
  'token',
  'pem',
  'entropy',
]);

/**
 * Split a field name into lower-case words across `_`, `-` and camelCase boundaries.
 *
 * The previous version anchored on `^` or `_`, which in a camelCase codebase matched almost
 * nothing: `privateKey`, `derivedKey`, `apiKey`, `sessionToken` and `password` all passed. Python's
 * identical regex was safe only by accident, because `log(**fields)` pushes callers to snake_case.
 */
function words(field: string): string[] {
  return field
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[\s_\-.]+/)
    .map((word) => word.toLowerCase())
    .filter((word) => word.length > 0);
}

/** Thrown instead of printing something that looks like a secret. */
export class SecretInLogError extends Error {
  readonly shape: string;

  constructor(shape: string) {
    super(
      `refusing to log a value matching ${shape}. ` +
        'Log fingerprint(domain, secret) instead — see ts/src/logging.ts.',
    );
    this.name = 'SecretInLogError';
    this.shape = shape;
  }
}

/**
 * Refuse rather than redact.
 *
 * Redaction would let the call site stay wrong: the developer sees `[REDACTED]`, shrugs, and ships
 * a line that silently discards the information they wanted. Throwing surfaces the mistake while
 * it is still cheap, in a test rather than in a public log.
 *
 * This is a backstop, not the mechanism. It catches shapes it recognises; the mechanism is that
 * secrets are fingerprinted at the point they are handled. Do not read a passing check as proof
 * that a line is safe.
 */
function assertNoSecret(rendered: string): void {
  for (const {name, pattern} of SECRET_SHAPES) {
    if (pattern.test(rendered)) throw new SecretInLogError(name);
  }
}

/** A field whose *name* says it carries a secret must carry a fingerprint instead. */
function assertFieldNameIsSafe(field: string): void {
  if (field.endsWith('_fp')) return;
  if (words(field).some((word) => SUSPICIOUS_WORDS.has(word))) {
    throw new SecretInLogError(`field named \`${field}\``);
  }
}

/** A `_fp` field must actually carry a fingerprint, not merely be named like one. */
function assertFingerprintShaped(field: string, value: unknown): void {
  if (!field.endsWith('_fp')) return;
  if (typeof value !== 'string' || !/^[0-9a-f]{16}$/.test(value)) {
    throw new SecretInLogError(
      `field \`${field}\` claims to be a fingerprint but is not 16 lower-case hex characters`,
    );
  }
}

export type LogFields = Record<string, string | number | boolean | null>;

/**
 * Structured log line, checked before it is emitted.
 *
 * Assume every line is public. It very likely is.
 */
export function log(event: string, fields: LogFields = {}): void {
  for (const [field, value] of Object.entries(fields)) {
    assertFieldNameIsSafe(field);
    assertFingerprintShaped(field, value);
  }
  // `event` last, so a caller-supplied `event` field cannot rename the event. It could before, and
  // a log line whose name is attacker-chosen is one that hides from every filter looking for it.
  const line = JSON.stringify({...fields, event});
  assertNoSecret(line);
  // eslint-disable-next-line no-console -- stdout is the transport; see the module docs.
  console.log(line);
}

/** Exported for tests, which need to assert that the backstop actually catches these shapes. */
export const _internal = {assertNoSecret, assertFieldNameIsSafe, assertFingerprintShaped, words, SECRET_SHAPES, SUSPICIOUS_WORDS};
