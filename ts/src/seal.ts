/**
 * Sealing an export bundle to a key only the holder holds.
 *
 * ## Why this exists at all
 *
 * Ownership that cannot survive the custodian is not ownership; it is very good tenancy (ADR 0010).
 * A holder must be able to get their own data out — when a provider exits a region, when they move
 * to another TEE provider, when an account is suspended in error, or simply for a backup.
 *
 * ## Why the encryption happens here rather than at the edge
 *
 * Invariant I7, as amended: *no plaintext state leaves the CVM except to the holder, under explicit
 * holder authorization, **encrypted in transit to a key only they hold***.
 *
 * So the bundle is sealed **inside the enclave**, before it is returned. Encrypting at the transport
 * layer instead would mean plaintext crossing the boundary and being re-protected by something
 * outside it, which is precisely the exposure I7 exists to prevent — the orchestrator, the host, and
 * anyone who can read a response body would all see it.
 *
 * ## The construction
 *
 * X25519 ECDH to an ephemeral key, HKDF-SHA256 to derive, AES-256-GCM to encrypt. All from Node's
 * built-in `crypto` — a template that pulls a cryptography dependency imposes that dependency, and
 * its future vulnerabilities, on every app cloned from it.
 *
 * **Ephemeral sender key, every time.** The enclave's own derived key is never used for this. If it
 * were, one compromise would retroactively open every bundle ever exported; with an ephemeral key
 * the private half is discarded when the call returns and forward secrecy is free.
 *
 * The HKDF `info` binds the licence and instance, so a bundle cannot be presented as an export of a
 * different instance — the recipient's own decryption fails if the context does not match.
 */

import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';

/** Wire format identifier. Present so a future construction is distinguishable, not guessed at. */
export const BUNDLE_VERSION = 'verity-export-v1' as const;

/**
 * RFC 7748 §6.1 — points whose shared secret is degenerate.
 *
 * Node performs no point validation on import, so one of these parses cleanly and then fails inside
 * the ECDH with a raw OpenSSL string that reaches the holder through `export failed: …`. Rejected
 * here, where the message can say what is actually wrong. Python rejects the same set; a difference
 * would mean one implementation seals what the other refuses.
 */
const SMALL_ORDER_POINTS: ReadonlySet<string> = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
  '4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
  'd9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
]);

export interface SealedBundle {
  readonly version: typeof BUNDLE_VERSION;
  /** Ephemeral X25519 public key, hex. The recipient needs it to derive the same secret. */
  readonly ephemeralPublicKey: string;
  /** AES-GCM initialisation vector, hex. */
  readonly iv: string;
  /** Ciphertext, base64. */
  readonly ciphertext: string;
  /** GCM authentication tag, hex. */
  readonly tag: string;
}

export class SealError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'SealError';
  }
}

/** Context bound into the derived key, so a bundle cannot be passed off as a different export. */
export interface SealContext {
  readonly licenseId: bigint;
  readonly instanceId: string;
}

function contextInfo(context: SealContext): Buffer {
  return Buffer.from(
    `${BUNDLE_VERSION}|license=${context.licenseId}|instance=${context.instanceId.toLowerCase()}`,
    'utf8',
  );
}

/**
 * Parse a holder-supplied X25519 public key.
 *
 * Raw 32 bytes, hex, with or without `0x`. Refuses anything else rather than guessing at a format —
 * a misparsed key encrypts to something the holder cannot open, and they find that out when they
 * need the data.
 */
export function parseRecipientKey(hex: string): KeyObject {
  const raw = hex.trim().replace(/^0x/, '');
  if (raw.length !== 64 || !/^[0-9a-f]+$/i.test(raw)) {
    throw new SealError(
      `recipient public key must be 32 bytes of hex (X25519), got ${raw.length} characters`,
    );
  }
  if (SMALL_ORDER_POINTS.has(raw.toLowerCase())) {
    throw new SealError(
      'recipient public key is a small-order X25519 point; the shared secret would be ' +
        'predictable, so nothing will be sealed to it',
    );
  }
  // SPKI prefix for X25519, so Node accepts a raw key without the caller having to wrap it.
  const spki = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    Buffer.from(raw, 'hex'),
  ]);
  try {
    return createPublicKey({key: spki, format: 'der', type: 'spki'});
  } catch (err) {
    throw new SealError(`recipient public key is not a valid X25519 key: ${(err as Error).message}`);
  }
}

function deriveKey(shared: Buffer, salt: Buffer, context: SealContext): Buffer {
  return Buffer.from(hkdfSync('sha256', shared, salt, contextInfo(context), 32));
}

/**
 * Seal `plaintext` to `recipient`.
 *
 * The ephemeral private key is never returned and goes out of scope when this does.
 */
export function seal(
  plaintext: Uint8Array,
  recipient: KeyObject,
  context: SealContext,
): SealedBundle {
  const ephemeral = generateKeyPairSync('x25519');
  const shared = diffieHellman({privateKey: ephemeral.privateKey, publicKey: recipient});

  const iv = randomBytes(12);
  // The IV doubles as HKDF salt: it is already unique per call and already travels with the
  // bundle, so a second random value would add a field without adding entropy.
  const key = deriveKey(shared, iv, context);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  const ephemeralRaw = ephemeral.publicKey.export({format: 'der', type: 'spki'}).subarray(-32);

  return {
    version: BUNDLE_VERSION,
    ephemeralPublicKey: Buffer.from(ephemeralRaw).toString('hex'),
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('hex'),
  };
}

/**
 * Open a bundle with the holder's private key.
 *
 * Not used by the app — the app never decrypts an export. It exists so the template's tests can
 * prove the holder can actually open what was sealed, and so a holder-side tool has a reference
 * implementation to match. **An export that cannot be opened is worse than no export**, because it
 * is discovered only when the data is needed.
 */
export function open(
  bundle: SealedBundle,
  recipientPrivateKey: KeyObject,
  context: SealContext,
): Buffer {
  if (bundle.version !== BUNDLE_VERSION) {
    throw new SealError(`unsupported bundle version ${String(bundle.version)}`);
  }

  let shared: Buffer;
  let iv: Buffer;
  try {
    const spki = Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      Buffer.from(bundle.ephemeralPublicKey, 'hex'),
    ]);
    const ephemeralPublic = createPublicKey({key: spki, format: 'der', type: 'spki'});
    shared = diffieHellman({privateKey: recipientPrivateKey, publicKey: ephemeralPublic});
    iv = Buffer.from(bundle.iv, 'hex');
  } catch (err) {
    // One error type for everything a malformed bundle can raise. These strings reach a holder
    // through `export failed: …`, and a raw OpenSSL message tells them nothing.
    throw new SealError(`bundle is malformed: ${(err as Error).message}`);
  }

  const key = deriveKey(shared, iv, context);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(Buffer.from(bundle.tag, 'hex'));
  try {
    return Buffer.concat([
      decipher.update(Buffer.from(bundle.ciphertext, 'base64')),
      decipher.final(),
    ]);
  } catch {
    // GCM authentication covers tampering *and* a mismatched context, since the context is in the
    // derived key. Both mean "this is not a bundle you can trust", so they report the same way.
    throw new SealError('bundle failed authentication: wrong key, wrong context, or tampered');
  }
}

/** Convenience for tests and holder-side tooling: a fresh X25519 keypair. */
export function generateRecipientKeypair(): {publicKeyHex: string; privateKey: KeyObject} {
  const pair = generateKeyPairSync('x25519');
  const raw = pair.publicKey.export({format: 'der', type: 'spki'}).subarray(-32);
  return {publicKeyHex: Buffer.from(raw).toString('hex'), privateKey: pair.privateKey};
}
