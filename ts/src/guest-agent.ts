/**
 * Client for the dStack guest agent.
 *
 * ## The socket is `tappd.sock`
 *
 * Measured on dstack 0.5.7: the guest agent answers on `/var/run/tappd.sock`. **`dstack.sock`
 * returns 404 for every method**, including the ones its own newer documentation describes. The
 * newer name appears in current docs and does not work on the version we deploy, so this client
 * targets the working socket and treats the other as a future migration rather than an alternative
 * to try.
 *
 * Both `DeriveKey` and `Tappd.DeriveKey` spellings were verified to return the *same* key for the
 * same path, so the prefix is cosmetic on 0.5.7. The unprefixed form is used here.
 *
 * Re-verify on any dstack version bump. This is version-coupled by nature, and the failure mode
 * of guessing is a container that starts and then cannot obtain its own keys.
 *
 * ## What this module deliberately does not do
 *
 * It does not decide anything. A derived key is returned, never logged; `health` and `migrate`
 * handler logic lives in `handlers/` and takes plain arguments, so the guest agent stays a thin
 * adapter. That separation is required by the app-lifecycle RFC's transport question: dStack is a
 * hard dependency of the platform, but it must not be a hard dependency of your business logic.
 */

import {request} from 'node:http';

import {fingerprint, log} from './logging.ts';

/** Where the guest agent listens. Overridable for the simulator, which uses a different path. */
export const DEFAULT_SOCKET_PATH = process.env.DSTACK_SOCKET ?? '/var/run/tappd.sock';

/** A request to the guest agent failed. */
export class GuestAgentError extends Error {
  readonly method: string;
  readonly status: number | undefined;

  constructor(method: string, status: number | undefined, detail: string) {
    super(`guest agent ${method} failed${status === undefined ? '' : ` (${status})`}: ${detail}`);
    this.name = 'GuestAgentError';
    this.method = method;
    this.status = status;
  }
}

/** Identity of this CVM, as the platform reports it. */
export interface InstanceInfo {
  /** Stable across an in-place upgrade. State continuity follows this, not `compose_hash`. */
  readonly appId: string;
  /** This particular running instance. */
  readonly instanceId: string;
  /** The configuration currently measured into `MR-CONFIG-ID`. Changes on upgrade. */
  readonly composeHash: string;
}

/** A key derived by the KMS for a given path. */
export interface DerivedKey {
  /** PEM-encoded P-256 private key. **Never log this.** */
  readonly privateKeyPem: string;
  /** The certificate chain the platform issued alongside it. */
  readonly certificateChain: readonly string[];
}

export interface GuestAgentOptions {
  readonly socketPath?: string;
  readonly timeoutMs?: number;
}

export class GuestAgent {
  private readonly socketPath: string;
  private readonly timeoutMs: number;

  constructor(options: GuestAgentOptions = {}) {
    this.socketPath = options.socketPath ?? DEFAULT_SOCKET_PATH;
    // Explicit rather than left to Node's default, which is no timeout at all. An agent that
    // accepts the connection and then stalls would hang a health check forever, and "forever" is
    // indistinguishable from "unhealthy" only after someone notices.
    this.timeoutMs = options.timeoutMs ?? 5_000;
  }

  /** Identity of this CVM. */
  async info(): Promise<InstanceInfo> {
    const raw = await this.call('GET', 'Info');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const appId = requireString(parsed, 'app_id', 'Info');
    const instanceId = requireString(parsed, 'instance_id', 'Info');
    // Present under different spellings across versions; absent is not fatal for `health`, so it
    // degrades to empty rather than refusing to start.
    const composeHash =
      typeof parsed.compose_hash === 'string'
        ? parsed.compose_hash
        : typeof parsed.app_compose_hash === 'string'
          ? parsed.app_compose_hash
          : '';
    return {appId, instanceId, composeHash};
  }

  /**
   * Derive a key for `path`.
   *
   * Deterministic for a given `(app_id, path)`, and — measured across a real in-place upgrade —
   * **stable when the app is upgraded in place**, because derivation is rooted in `app_id` which
   * the upgrade preserves. A *fresh deploy* gets a new `app_id` and therefore a different key, with
   * no error anywhere: the instance comes up working, with keys that cannot read anything the
   * previous one wrote.
   *
   * The returned key is never logged. Its fingerprint is, so an operator can confirm continuity
   * across an upgrade without the value ever reaching stdout.
   */
  async deriveKey(path: string, subject = path): Promise<DerivedKey> {
    const raw = await this.call('POST', 'DeriveKey', {path, subject});
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const privateKeyPem = requireString(parsed, 'key', 'DeriveKey');
    const chain = Array.isArray(parsed.certificate_chain)
      ? parsed.certificate_chain.filter((c): c is string => typeof c === 'string')
      : [];

    log('derived_key', {path, key_fp: fingerprint('derived-key', privateKeyPem)});
    return {privateKeyPem, certificateChain: chain};
  }

  /**
   * Request a TDX quote over `reportData`.
   *
   * Returned raw. **Do not hand a caller a parsed rendering of a quote and call it evidence** —
   * a verifier must parse the raw quote itself, because the signature covers the quote and not
   * anyone's summary of it.
   */
  async tdxQuote(reportData: Uint8Array): Promise<string> {
    const raw = await this.call('POST', 'TdxQuote', {
      report_data: Buffer.from(reportData).toString('hex'),
    });
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return requireString(parsed, 'quote', 'TdxQuote');
  }

  private call(httpMethod: 'GET' | 'POST', method: string, body?: unknown): Promise<string> {
    const payload = body === undefined ? undefined : JSON.stringify(body);

    return new Promise((resolve, reject) => {
      const req = request(
        {
          socketPath: this.socketPath,
          path: `/prpc/${method}`,
          method: httpMethod,
          headers:
            payload === undefined
              ? {}
              : {
                  'content-type': 'application/json',
                  'content-length': Buffer.byteLength(payload),
                },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            const status = res.statusCode ?? 0;
            if (status < 200 || status >= 300) {
              // 404 here almost always means the wrong socket — see the module docs.
              reject(new GuestAgentError(method, status, text.slice(0, 200)));
              return;
            }
            resolve(text);
          });
        },
      );

      req.setTimeout(this.timeoutMs, () => {
        req.destroy();
        reject(new GuestAgentError(method, undefined, `timed out after ${this.timeoutMs}ms`));
      });
      req.on('error', (err) => reject(new GuestAgentError(method, undefined, err.message)));

      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }
}

function requireString(obj: Record<string, unknown>, key: string, method: string): string {
  const value = obj[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new GuestAgentError(method, undefined, `response has no \`${key}\``);
  }
  return value;
}
