/**
 * Publish-time check: is this compose safe to bind a licence to?
 *
 * ## Why a check on this side matters even though the verifier also checks
 *
 * The verifier catches a tag-referenced compose on the *holder's* side, which is the enforcement a
 * publisher cannot route around. But by then the record is published, and version records are
 * append-only (I5) — the mistake is permanent and every holder of that version is refused forever.
 *
 * So this runs before publishing, where the mistake is still free. It is a convenience, not the
 * guarantee; the guarantee lives in `verity-verifier` precisely because a publisher can skip
 * anything that runs on their own machine.
 *
 * ## The failure it prevents
 *
 * A tag is a name the registry can repoint. The compose text does not change when it does, so
 * `composeHash` stays stable, `MR-CONFIG-ID` stays stable, attestation keeps passing, and the code
 * executing is whatever the registry now serves. **Every check succeeds and the guarantee is gone**
 * — which is worse than a check that fails, because nobody is looking.
 *
 * dStack's own reference compose uses a bare tag. This is not an exotic mistake.
 */

import {createHash} from 'node:crypto';

/** A digest-pinned image reference. Constructing one asserts it is pinned; a tag cannot become one. */
export interface PinnedImage {
  readonly service: string;
  readonly reference: string;
  /** The `sha256:…` portion. */
  readonly digest: string;
}

export class ComposeCheckError extends Error {
  readonly reason: string;

  constructor(reason: string, detail: string) {
    super(detail);
    this.name = 'ComposeCheckError';
    this.reason = reason;
  }
}

/**
 * `sha256` of the exact bytes.
 *
 * Not `keccak256`. This must match what the platform measures into `MR-CONFIG-ID` and what the
 * verifier recomputes; the wrong hash function produces a record that looks entirely well-formed
 * and can never be satisfied by any deployment.
 *
 * Takes bytes rather than an object, because the hash is over the file as served. Re-serialising a
 * parsed object changes whitespace and therefore the hash.
 */
export function composeHash(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Accepts `repo@sha256:<64 hex>` and nothing else.
 *
 * A truncated or malformed digest is not a weaker pin — it is not a pin.
 */
function classify(reference: string): string | undefined {
  const at = reference.indexOf('@');
  if (at < 0) return undefined;
  const digest = reference.slice(at + 1);
  const [algorithm, hex] = digest.split(':');
  if (algorithm !== 'sha256' || hex === undefined) return undefined;
  if (hex.length !== 64 || !/^[0-9a-f]+$/i.test(hex)) return undefined;
  return digest;
}

/**
 * Extract every image, refusing if any is not digest-pinned.
 *
 * Deliberately a line scanner rather than a YAML parse: the embedded compose is a string inside
 * JSON, adding a YAML dependency to a template is a cost every copy inherits, and the property
 * being checked is textual. A service using an exotic YAML form this misses would be caught by the
 * verifier — the enforcement that matters is on the other side.
 *
 * @throws {ComposeCheckError} when the document declares no images, or any image carries a tag
 */
export function pinnedImages(composeDocument: Uint8Array): PinnedImage[] {
  let outer: {docker_compose_file?: unknown};
  try {
    outer = JSON.parse(new TextDecoder().decode(composeDocument)) as typeof outer;
  } catch (err) {
    throw new ComposeCheckError('not-json', `compose is not valid JSON: ${(err as Error).message}`);
  }

  const inner = outer.docker_compose_file;
  if (typeof inner !== 'string') {
    throw new ComposeCheckError('no-compose-file', 'compose has no `docker_compose_file` string');
  }

  const found: PinnedImage[] = [];
  let currentService = '<unknown>';
  for (const rawLine of inner.split('\n')) {
    const serviceMatch = /^ {2}([A-Za-z0-9._-]+):\s*$/.exec(rawLine);
    if (serviceMatch?.[1] !== undefined) currentService = serviceMatch[1];

    const imageMatch = /^\s*image:\s*(\S+)\s*$/.exec(rawLine);
    const reference = imageMatch?.[1];
    if (reference === undefined) continue;

    const digest = classify(reference.replace(/^["']|["']$/g, ''));
    if (digest === undefined) {
      throw new ComposeCheckError(
        'not-pinned',
        `service \`${currentService}\` references image \`${reference}\` by tag, not digest. ` +
          'A tag lets the registry change what runs while composeHash stays stable, so every ' +
          'downstream check passes and the guarantee is gone (I8, ADR 0007).',
      );
    }
    found.push({service: currentService, reference, digest});
  }

  if (found.length === 0) {
    // Refused rather than vacuously passed: a document with nothing to check is not a document
    // that passed the check.
    throw new ComposeCheckError('no-images', 'compose declares no images');
  }
  return found;
}

/**
 * Normalise a licensed image digest to the lowercase `sha256:<64hex>` form `pinnedImages` produces.
 *
 * Accepts every form a caller might reasonably hold: `sha256:<64hex>`, bare `<64hex>`, or
 * `0x<64hex>`. Exported so every place that needs to *print* the digest a check ran against shows
 * the same value the check actually compared — a caller re-deriving this independently is exactly
 * how a display string and a check drift.
 *
 * This normalises; it does not validate. Garbage in yields `sha256:garbage` out — the `0x`/`sha256:`
 * prefix strips are themselves case-sensitive (`0X…` or `SHA256:…` pass through unstripped), so a
 * malformed or oddly-cased prefix produces a value that then simply fails the comparison in
 * `assertReferencesDigest` (a `digest-absent` refusal), rather than being rejected here by name.
 */
export function normaliseImageDigest(imageDigest: string): string {
  const stripped = imageDigest.startsWith('0x') ? imageDigest.slice(2) : imageDigest;
  const withPrefix = stripped.startsWith('sha256:') ? stripped : `sha256:${stripped}`;
  return withPrefix.toLowerCase();
}

/**
 * Check the compose actually references the digest the manifest record will name.
 *
 * Gives `imageDigest` a job beyond human readability: it becomes the value the compose is checked
 * *against*, closing the loop between the two fields of a record.
 */
export function assertReferencesDigest(composeDocument: Uint8Array, imageDigest: string): void {
  const normalised = normaliseImageDigest(imageDigest);
  const images = pinnedImages(composeDocument);
  if (!images.some((image) => image.digest.toLowerCase() === normalised)) {
    throw new ComposeCheckError(
      'digest-absent',
      `compose does not reference the licensed image digest ${normalised}; it references ` +
        images.map((image) => image.digest).join(', '),
    );
  }
}
