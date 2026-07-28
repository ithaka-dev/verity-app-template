/**
 * The holder's migration authorization: an EIP-712 typed struct.
 *
 * ## Why the holder signs at all
 *
 * The orchestrator asks this app to migrate. The app must not simply believe it. Spec §2.8's whole
 * direction is that the orchestrator becomes untrusted — permissionless workers, gated by
 * attestation — and an app that migrates because a box told it to has made that box trusted again
 * at exactly the moment it is mutating the holder's data.
 *
 * So the orchestrator is a *carrier* of a holder-signed fact, never its author. This is invariant
 * I3 applied one layer in.
 *
 * ## Why a mint is not this signature
 *
 * Minting the new licence says "I want this version." This says "move *this instance's* data from
 * A to B." A holder may legitimately want the new version without their running instance being
 * touched — to evaluate it alongside, or to migrate at a quieter moment. **Never migrate because
 * you observed a mint** (I10). An implementation can honour ADR 0003 to the letter and still move
 * someone's data unasked; this is the separate thing that stops it.
 *
 * ## Why every field is in the struct
 *
 * Each one closes a way a signature could be reused for something the holder did not authorize.
 * Dropping any of them leaves a valid signature usable somewhere it was not meant to go.
 */

import {hashTypedData, type Address, type Hex, type TypedDataDomain} from 'viem';

/** EIP-712 type definition. The wire contract — changing it invalidates every existing signature. */
export const MIGRATION_AUTHORIZATION_TYPES = {
  MigrationAuthorization: [
    {name: 'licenseId', type: 'uint256'},
    {name: 'fromDigest', type: 'bytes32'},
    {name: 'toDigest', type: 'bytes32'},
    {name: 'instanceId', type: 'bytes32'},
    {name: 'nonce', type: 'uint256'},
    {name: 'expiry', type: 'uint256'},
  ],
} as const;

export interface MigrationAuthorization {
  /** Which entitlement authorizes this. */
  readonly licenseId: bigint;
  /**
   * The instance being migrated *from*.
   *
   * Without it a signature is reusable against a different instance the same holder owns — they
   * authorized moving one thing and moved another.
   */
  readonly fromDigest: Hex;
  /** The version being migrated *to*. */
  readonly toDigest: Hex;
  /**
   * Binds to one specific running instance.
   *
   * `fromDigest` alone is not enough: a holder running two instances of the same version has two
   * things matching it.
   */
  readonly instanceId: Hex;
  /** Prevents replay of a previously valid authorization. */
  readonly nonce: bigint;
  /** Bounds the window in which a leaked signature is useful. */
  readonly expiry: bigint;
}

/**
 * A holder's authorization to export their own data.
 *
 * @dev Same mechanism as the migration authorization, and deliberately a **different struct** —
 * `MigrationAuthorization` and this one must not be interchangeable. That lesson was learned
 * expensively one repo over: `LicenseToken.mint` and `upgrade` shared a signed struct, which made
 * every check in `upgrade` decorative because an authorization for one could be spent on the other.
 * Two operations, two types, two typehashes.
 *
 * `recipientPublicKey` is in the signature because it decides *who can read the result*. Left out,
 * a relayer could substitute their own key and receive a bundle the holder authorized — the export
 * would be genuinely authorized and delivered to the wrong person.
 */
export const EXPORT_AUTHORIZATION_TYPES = {
  ExportAuthorization: [
    {name: 'licenseId', type: 'uint256'},
    {name: 'instanceId', type: 'bytes32'},
    {name: 'recipientPublicKey', type: 'bytes32'},
    {name: 'nonce', type: 'uint256'},
    {name: 'expiry', type: 'uint256'},
  ],
} as const;

export interface ExportAuthorization {
  readonly licenseId: bigint;
  readonly instanceId: Hex;
  /** X25519 public key the bundle will be sealed to. 32 bytes. */
  readonly recipientPublicKey: Hex;
  readonly nonce: bigint;
  readonly expiry: bigint;
}

/** The digest a holder signs to authorize an export. */
export function hashExportAuthorization(
  authorization: ExportAuthorization,
  chainId: number,
  licenseToken: Address,
): Hex {
  return hashTypedData({
    domain: migrationDomain(chainId, licenseToken),
    types: EXPORT_AUTHORIZATION_TYPES,
    primaryType: 'ExportAuthorization',
    message: authorization,
  });
}

/**
 * Check an export authorization describes this instance, right now.
 *
 * @throws {AuthorizationExpiredError} past its expiry
 * @throws {AuthorizationMismatchError} for a different instance
 */
export function assertExportAuthorizationMatches(
  authorization: ExportAuthorization,
  expectedInstanceId: Hex,
  now: bigint,
): void {
  if (now > authorization.expiry) {
    throw new AuthorizationExpiredError(authorization.expiry, now);
  }
  assertLifetimeIsBounded(authorization.expiry, now);
  assertFieldEquals('instanceId', expectedInstanceId, authorization.instanceId);
}

/**
 * The EIP-712 domain.
 *
 * `chainId` prevents cross-chain replay. `verifyingContract` is the `LicenseToken` this app's
 * licences live in, which separates deployments — a signature for a testnet licence must not
 * verify against a mainnet one, and under ADR 0002 everything is testnet, so that separation is
 * doing real work right now rather than someday.
 */
export function migrationDomain(chainId: number, licenseToken: Address): TypedDataDomain {
  return {
    name: 'Verity App Lifecycle',
    version: '1',
    chainId,
    verifyingContract: licenseToken,
  };
}

/** The digest a holder signs. */
export function hashMigrationAuthorization(
  authorization: MigrationAuthorization,
  chainId: number,
  licenseToken: Address,
): Hex {
  return hashTypedData({
    domain: migrationDomain(chainId, licenseToken),
    types: MIGRATION_AUTHORIZATION_TYPES,
    primaryType: 'MigrationAuthorization',
    message: authorization,
  });
}

/**
 * The longest an authorization may claim to be valid for.
 *
 * A signature is a bearer capability for as long as it is valid, and the party holding it is the
 * orchestrator — the component spec §2.8 says must become untrusted. An unbounded expiry turns one
 * holder act into a standing permission, so the app refuses to honour one however genuinely it was
 * signed. The holder cannot grant more than this by choosing a larger number.
 */
export const MAX_AUTHORIZATION_LIFETIME_SECONDS = 3600n;

/** The authorization claims a validity window longer than the app will honour. */
export class AuthorizationLifetimeTooLongError extends Error {
  readonly expiry: bigint;
  readonly maximum: bigint;

  constructor(expiry: bigint, maximum: bigint) {
    super(
      `authorization is valid until ${expiry}, more than ${maximum}s ahead; refusing to honour a ` +
        'window this long — see MAX_AUTHORIZATION_LIFETIME_SECONDS',
    );
    this.name = 'AuthorizationLifetimeTooLongError';
    this.expiry = expiry;
    this.maximum = maximum;
  }
}

function assertLifetimeIsBounded(expiry: bigint, now: bigint): void {
  if (expiry > now + MAX_AUTHORIZATION_LIFETIME_SECONDS) {
    throw new AuthorizationLifetimeTooLongError(expiry, MAX_AUTHORIZATION_LIFETIME_SECONDS);
  }
}

/** The authorization does not describe the situation it was presented in. */
export class AuthorizationMismatchError extends Error {
  readonly field: string;
  readonly expected: string;
  readonly actual: string;

  constructor(field: string, expected: string, actual: string) {
    super(`migration authorization ${field} mismatch: expected ${expected}, got ${actual}`);
    this.name = 'AuthorizationMismatchError';
    this.field = field;
    this.expected = expected;
    this.actual = actual;
  }
}

/** The authorization's expiry has passed. */
export class AuthorizationExpiredError extends Error {
  readonly expiry: bigint;
  readonly now: bigint;

  constructor(expiry: bigint, now: bigint) {
    super(`migration authorization expired at ${expiry} (now ${now})`);
    this.name = 'AuthorizationExpiredError';
    this.expiry = expiry;
    this.now = now;
  }
}

/**
 * What the app independently knows about its own situation.
 *
 * **Every field here must come from somewhere other than the authorization.** Comparing an
 * authorization's field against itself type-checks, reads like a check, and verifies nothing — and
 * it is the natural shape to write by accident, because both values are right there.
 */
export interface ExpectedContext {
  /**
   * The compose hash this instance is running *now*, from the guest agent.
   *
   * Compared against `toDigest`. After an in-place upgrade the instance has already restarted on
   * the new configuration, so the version being migrated *to* is the one currently executing —
   * which makes this the one digest the app can verify from the platform rather than from the
   * message.
   */
  readonly runningComposeHash: Hex;
  /**
   * The compose hash recorded at the previous boot, or `null` if this instance has never recorded
   * one.
   *
   * Compared against `fromDigest` when known. `null` is not a failure: a first boot legitimately
   * has no previous hash, and refusing then would make an instance unable to perform its first
   * migration. The signature still binds `fromDigest`, so a leaked authorization remains unusable
   * against an instance running a different source version — the on-app check is a second line,
   * not the only one.
   */
  readonly previousComposeHash: Hex | null;
  /** This instance, from the guest agent. */
  readonly instanceId: Hex;
}

/**
 * Check the authorization describes *this* migration, on *this* instance, right now.
 *
 * Signature validity is a separate question and answered in `signature.ts`. Both must hold: a
 * genuine signature over the wrong instance is exactly the attack the `instanceId` field exists to
 * stop, and it would pass a signature check alone.
 *
 * `now` is passed in rather than read from a clock so this stays pure and testable, and so a
 * caller has to be explicit about where its notion of time came from.
 */
export function assertAuthorizationMatches(
  authorization: MigrationAuthorization,
  expected: ExpectedContext,
  now: bigint,
): void {
  if (now > authorization.expiry) {
    throw new AuthorizationExpiredError(authorization.expiry, now);
  }
  assertLifetimeIsBounded(authorization.expiry, now);
  assertFieldEquals('toDigest', expected.runningComposeHash, authorization.toDigest);
  assertFieldEquals('instanceId', expected.instanceId, authorization.instanceId);
  if (expected.previousComposeHash !== null) {
    assertFieldEquals('fromDigest', expected.previousComposeHash, authorization.fromDigest);
  }
}

/** Hex comparison is case-insensitive; a checksum difference is not a mismatch. */
function assertFieldEquals(field: string, expected: Hex, actual: Hex): void {
  if (expected.toLowerCase() !== actual.toLowerCase()) {
    throw new AuthorizationMismatchError(field, expected, actual);
  }
}
