/**
 * Signature verification that dispatches on account type.
 *
 * ## Read this before changing anything here
 *
 * `ecrecover` recovers an ECDSA signer and works **only for an EOA**. The moment a holder's account
 * is an ERC-4337 smart account there is no key to recover, and verification silently has no valid
 * path. That is not speculative — it is precisely the failure already documented for x402's
 * recommended EIP-3009 payment method, which turned out to be EOA-only.
 *
 * ADR 0002 defers account abstraction, so the EOA branch is sufficient for MVP. But that same ADR
 * makes AA a **hard gate on any real-value deployment**, which means every app written against
 * bare `ecrecover` breaks at that gate. And apps built from this template are third-party software
 * nobody can patch.
 *
 * **So the dispatch exists from the first published version, even though one branch throws.** The
 * shape is the deliverable. Filling in ERC-1271 later is adding a case to a function; retrofitting
 * this structure into a hundred cloned apps is not possible at all.
 *
 * ## Why the smart-account branch throws rather than returning false
 *
 * "Not supported yet" and "your signature is wrong" are different problems and only one of them is
 * the caller's. A holder with a contract wallet who gets `invalid signature` will go looking for a
 * bug in their signer. An absent branch is also indistinguishable from an unconsidered one — the
 * explicit throw is what tells a reader this was decided rather than missed.
 */

import {recoverTypedDataAddress, type Address, type Hex, type PublicClient} from 'viem';

import {MIGRATION_AUTHORIZATION_TYPES, migrationDomain, type MigrationAuthorization} from './authorization.ts';

/** The signer is a contract account, which this version cannot verify. */
export class SmartAccountNotSupportedError extends Error {
  readonly account: Address;

  constructor(account: Address) {
    super(
      `${account} is a contract account. ERC-1271 verification is not implemented in MVP ` +
        '(ADR 0002 defers account abstraction). This is a known gap, not a signature failure.',
    );
    this.name = 'SmartAccountNotSupportedError';
    this.account = account;
  }
}

/** The recovered signer is not the account that was required. */
export class SignerMismatchError extends Error {
  readonly expected: Address;
  readonly recovered: Address;

  constructor(expected: Address, recovered: Address) {
    super(`signature recovers to ${recovered}, expected ${expected}`);
    this.name = 'SignerMismatchError';
    this.expected = expected;
    this.recovered = recovered;
  }
}

/** Whether an address currently has contract code deployed at it. */
export async function isContractAccount(client: PublicClient, account: Address): Promise<boolean> {
  const code = await client.getCode({address: account});
  return code !== undefined && code !== '0x';
}

/**
 * Verify `signature` over a migration authorization was produced by `signer`.
 *
 * Throws on every failure rather than returning a boolean. A boolean invites `if (ok)` with no
 * else, and the else is the branch that matters when the action is mutating someone's data.
 *
 * @throws {SmartAccountNotSupportedError} the signer is a contract account
 * @throws {SignerMismatchError} the signature is valid but for a different account
 */
export async function verifyMigrationSignature(options: {
  readonly client: PublicClient;
  readonly signer: Address;
  readonly authorization: MigrationAuthorization;
  readonly chainId: number;
  readonly licenseToken: Address;
  readonly signature: Hex;
}): Promise<void> {
  const {client, signer, authorization, chainId, licenseToken, signature} = options;

  // Dispatch first, so a contract account never reaches ECDSA recovery. Recovery against a
  // contract account does not fail loudly — it returns *some* address, which is then compared and
  // found unequal, producing "invalid signature" for what is actually an unsupported account type.
  if (await isContractAccount(client, signer)) {
    // ERC-1271 goes here: `client.verifyTypedData({address: signer, ...})` already dispatches to
    // `isValidSignature` for contract accounts. Deliberately not enabled — the rest of the system
    // refuses smart accounts too (see `SignatureChecker.sol`), and an app that accepted one while
    // `LicenseToken` could not mint to it would produce a half-working story that is worse than a
    // clear refusal. Enable both together, or neither.
    throw new SmartAccountNotSupportedError(signer);
  }

  const recovered = await recoverTypedDataAddress({
    domain: migrationDomain(chainId, licenseToken),
    types: MIGRATION_AUTHORIZATION_TYPES,
    primaryType: 'MigrationAuthorization',
    message: authorization,
    signature,
  });

  if (recovered.toLowerCase() !== signer.toLowerCase()) {
    throw new SignerMismatchError(signer, recovered);
  }
}
