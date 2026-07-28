/**
 * Configuration, read from the environment — which means read from the measured compose.
 *
 * ## Why this is a security boundary and not plumbing
 *
 * Every value here comes from `app-compose.json`, and `app-compose.json` is what `composeHash`
 * hashes and `MR-CONFIG-ID` measures. So each of these is covered by attestation: a holder
 * verifying this app before use is also verifying *which RPC endpoint it will trust* and *which
 * LicenseToken it will believe*.
 *
 * That is the entire point of pinning the RPC endpoint in the compose rather than fetching it,
 * defaulting it, or accepting it from a caller. An app that picks up its chain endpoint at runtime
 * has an unmeasured trust dependency: the attestation says what code runs, and the code asks
 * somebody unspecified what the chain says. Whoever answers decides who the holder is.
 *
 * **Consequence to accept deliberately: changing the RPC endpoint changes `composeHash`, which is a
 * new version that holders must choose to move to.** That is inconvenient and it is correct — an
 * operator who could swap the endpoint silently could redirect the app's notion of ownership
 * without any holder noticing.
 *
 * Nothing here is a secret (C2/C5): endpoints and addresses are public. If you find yourself
 * wanting to add a key to this file, that is the signal to stop.
 */

import {getAddress, isAddress, type Address} from 'viem';

/** A required configuration value was missing or malformed. */
export class ConfigError extends Error {
  constructor(variable: string, detail: string) {
    super(
      `${variable} ${detail}. It must be set in app-compose.json so it is covered by ` +
        'composeHash — see ts/src/config.ts.',
    );
    this.name = 'ConfigError';
  }
}

export interface AppConfig {
  /** Chain the licence lives on. */
  readonly chainId: number;
  /** Pinned in the compose, and therefore measured. */
  readonly rpcUrl: string;
  /** The `LicenseToken` contract. */
  readonly licenseToken: Address;
  /** This app's `AppManifest` — its identity (ADR 0011). */
  readonly appManifest: Address;
  /** The version this instance is running, as published in the manifest. */
  readonly version: string;
  /**
   * Whether container logs are publicly retrievable.
   *
   * Defaults to `true` because that is what the platform defaults to, and a template that assumed
   * the safer value would teach developers to expect privacy they do not have.
   */
  readonly publicLogs: boolean;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return {
    chainId: requireInt(env, 'VERITY_CHAIN_ID'),
    rpcUrl: requireUrl(env, 'VERITY_RPC_URL'),
    licenseToken: requireAddress(env, 'VERITY_LICENSE_TOKEN'),
    appManifest: requireAddress(env, 'VERITY_APP_MANIFEST'),
    version: requireString(env, 'VERITY_VERSION'),
    publicLogs: env.VERITY_PUBLIC_LOGS !== 'false',
  };
}

function requireString(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim() === '') throw new ConfigError(name, 'is not set');
  return value.trim();
}

function requireInt(env: NodeJS.ProcessEnv, name: string): number {
  const raw = requireString(env, name);
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ConfigError(name, `is not a positive integer (got ${raw})`);
  }
  return parsed;
}

function requireAddress(env: NodeJS.ProcessEnv, name: string): Address {
  const raw = requireString(env, name);
  if (!isAddress(raw)) throw new ConfigError(name, `is not an address (got ${raw})`);
  return getAddress(raw);
}

function requireUrl(env: NodeJS.ProcessEnv, name: string): string {
  const raw = requireString(env, name);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ConfigError(name, `is not a URL (got ${raw})`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ConfigError(name, `must be http or https (got ${parsed.protocol})`);
  }
  return raw;
}
