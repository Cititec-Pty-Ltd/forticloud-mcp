import { AsyncLocalStorage } from 'node:async_hooks';
import { logger } from './utils/logger.js';
import { fetchWithRateLimitRetry } from './rate-limit.js';
import type { FetchFn } from './rate-limit.js';
import { ForticloudApiError, ForticloudAuthError, ForticloudRateLimitError } from './types.js';
import type { ForticloudConfig, Portal } from './types.js';

/** Largest response body read, in characters. */
const MAX_RESPONSE_CHARS = 20_000_000;
/** Wait reported for a 429 that does not say how long. */
const DEFAULT_RETRY_AFTER_SECONDS = 60;
/**
 * After FortiCloud refuses the credentials, no new password grant is tried for
 * this long: repeated failed grants can lock the API user out of every portal.
 */
const AUTH_FAILURE_HOLD_MS = 10 * 60_000;
/** A cached token is renewed this long before it expires. */
const TOKEN_MARGIN_MS = 120_000;
/** Lifetime assumed when the token answer has no expires_in. */
const DEFAULT_TOKEN_SECONDS = 3600;

export const DEFAULTS = {
  authUrl: 'https://customerapiauth.fortinet.com/api/v1/oauth/token/',
  assetUrl: 'https://support.fortinet.com/ES/api/registration/v3',
  fgtUrl: 'https://api.fortigate.forticloud.com/forticloudapi/v1',
  assetClientId: 'assetmanagement',
  fgtClientId: 'fortigatecloud',
} as const;

const PORTAL_NAME: Record<Portal, string> = { asset: 'Asset Management', fgt: 'FortiGate Cloud' };
const CLIENT_ID_ENV: Record<Portal, string> = { asset: 'FORTICLOUD_ASSET_CLIENT_ID', fgt: 'FORTICLOUD_FGT_CLIENT_ID' };

const CREDENTIAL_HINT =
  ' Check FORTICLOUD_API_ID and FORTICLOUD_API_PASSWORD: the API user from FortiCloud > IAM > Users (type API User), copied from its credentials file.';
const DNS_HINT = ' The host name does not resolve from here; check DNS and outbound internet access.';

// Request-scoped configuration, for tests and embedding. The MCP host uses the
// process environment (the service's env file).
const configStore = new AsyncLocalStorage<ForticloudConfig>();

export function runWithConfig<T>(config: ForticloudConfig, fn: () => T): T {
  return configStore.run(config, fn);
}

/** Thrown when a FORTICLOUD_* setting is present but not usable. */
export class ConfigError extends Error {}

/** An https base URL with no query, fragment or credentials; the trailing slash is dropped unless `keepSlash`. */
export function parseBaseUrl(name: string, raw: string, keepSlash = false): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ConfigError(`${name} is not a valid URL.`);
  }
  if (url.protocol !== 'https:') throw new ConfigError(`${name} must start with https://.`);
  if (url.username || url.password) throw new ConfigError(`${name} must not contain a user name or password.`);
  if (url.search || url.hash) throw new ConfigError(`${name} must not have a query string or fragment.`);
  const path = keepSlash ? url.pathname : url.pathname.replace(/\/+$/, '');
  return `${url.origin}${path}`;
}

function clientId(name: string, raw: string | undefined, dflt: string): string {
  const v = raw?.trim() || dflt;
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(v)) throw new ConfigError(`${name} must be a FortiCloud client ID such as ${dflt}.`);
  return v;
}

export function getConfig(env: Record<string, string | undefined> = process.env): ForticloudConfig | null {
  const scoped = configStore.getStore();
  if (scoped?.apiId && scoped.apiPassword) return scoped;
  const apiId = env.FORTICLOUD_API_ID?.trim();
  const apiPassword = env.FORTICLOUD_API_PASSWORD?.trim();
  if (!apiId || !apiPassword) {
    logger.warn('Missing configuration', { hasApiId: Boolean(apiId), hasPassword: Boolean(apiPassword) });
    return null;
  }
  return {
    apiId,
    apiPassword,
    authUrl: parseBaseUrl('FORTICLOUD_AUTH_URL', env.FORTICLOUD_AUTH_URL?.trim() || DEFAULTS.authUrl, true),
    assetUrl: parseBaseUrl('FORTICLOUD_ASSET_URL', env.FORTICLOUD_ASSET_URL?.trim() || DEFAULTS.assetUrl),
    fgtUrl: parseBaseUrl('FORTICLOUD_FGT_URL', env.FORTICLOUD_FGT_URL?.trim() || DEFAULTS.fgtUrl),
    assetClientId: clientId('FORTICLOUD_ASSET_CLIENT_ID', env.FORTICLOUD_ASSET_CLIENT_ID, DEFAULTS.assetClientId),
    fgtClientId: clientId('FORTICLOUD_FGT_CLIENT_ID', env.FORTICLOUD_FGT_CLIENT_ID, DEFAULTS.fgtClientId),
  };
}

/** Removes the password, the API ID's secret part and any token from text that leaves this module. */
export function scrub(text: string, config: Pick<ForticloudConfig, 'apiPassword'>, extra: string[] = []): string {
  let out = text;
  for (const secret of [config.apiPassword, ...extra, ...liveTokens()]) {
    if (!secret || secret.length < 4) continue;
    out = out.split(secret).join('[REDACTED]');
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) out = out.split(encoded).join('[REDACTED]');
  }
  return out
    .replace(/("?(?:password|access_token|refresh_token|token)"?\s*[:=]\s*"?)[^"&\s,}]+/gi, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]');
}

// --- HTTP ------------------------------------------------------------------------------------

let fetchOverride: FetchFn | undefined;

/** Tests replace the network with a fake fetch. Also clears the token cache. */
export function setFetchForTests(fn?: FetchFn): void {
  fetchOverride = fn;
  tokens.clear();
  refused.clear();
}

function fetchFn(): FetchFn {
  return fetchOverride ?? ((url, init) => fetch(url, init));
}

function describeNetworkError(err: unknown, config: ForticloudConfig): string {
  const e = err as Error & { cause?: { code?: string; message?: string } };
  if (e.name === 'TimeoutError') return 'timed out';
  const code = e.cause?.code ?? '';
  const detail = scrub(`${e.cause?.message ?? e.message}`, config).slice(0, 200);
  const dns = /ENOTFOUND|EAI_AGAIN/.test(code);
  return `failed (${code || e.name}: ${detail}).${dns ? DNS_HINT : ''}`;
}

/** A short, scrubbed message from a FortiCloud error body (JSON or not). */
export function errorDetail(body: string, config: ForticloudConfig): string {
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of ['error_description', 'error', 'message', 'msg', 'detail']) {
      const v = parsed?.[key];
      if (typeof v === 'string' && v.trim()) parts.push(v.trim());
      else if (v && typeof v === 'object') {
        const inner = (v as Record<string, unknown>).message ?? (v as Record<string, unknown>).errorMessage;
        if (typeof inner === 'string' && inner.trim()) parts.push(inner.trim());
      }
    }
    if (parts.length) return scrub([...new Set(parts)].join(' - '), config).replace(/\s+/g, ' ').slice(0, 400);
  } catch {
    // not JSON
  }
  return scrub(body, config).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
}

function rateLimited(status: number, label: string, retryAfterMs: number | undefined): ForticloudRateLimitError {
  const wait = retryAfterMs !== undefined ? Math.max(1, Math.ceil(retryAfterMs / 1000)) : DEFAULT_RETRY_AFTER_SECONDS;
  return new ForticloudRateLimitError(`FortiCloud rate-limited the request (HTTP ${status}): ${label}. Try again in ${wait} s.`, wait);
}

interface RawResult {
  status: number;
  text: string;
}

/**
 * One HTTP request. `read` marks it replay-safe (every request this server
 * makes is a read, including Asset Management's POST queries and the token
 * request), so a short 429 is retried once. Throws ForticloudRateLimitError
 * for a 429 that is still there, ForticloudApiError for network trouble.
 */
async function send(
  config: ForticloudConfig,
  method: 'GET' | 'POST',
  url: string,
  label: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs = 60_000
): Promise<RawResult> {
  let result;
  try {
    result = await fetchWithRateLimitRetry(fetchFn(), url, label, true, () => ({
      method,
      headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    }));
  } catch (err) {
    throw new ForticloudApiError(`FortiCloud ${label} ${describeNetworkError(err, config)}`);
  }
  const { res } = result;
  if (res.status === 429 || (res.status === 503 && result.retryAfterMs !== undefined)) {
    throw rateLimited(res.status, label, result.retryAfterMs);
  }
  const length = Number(res.headers.get('content-length') ?? '0');
  if (length > MAX_RESPONSE_CHARS) {
    await res.body?.cancel().catch(() => undefined);
    throw new ForticloudApiError(`FortiCloud ${label}: response too large (${length} bytes)`, res.status);
  }
  const text = result.body ?? (await res.text());
  if (text.length > MAX_RESPONSE_CHARS) throw new ForticloudApiError(`FortiCloud ${label}: response too large`, res.status);
  return { status: res.status, text };
}

function parseJson(text: string, label: string, status: number): unknown {
  const trimmed = text.trimStart();
  if (trimmed === '') return {};
  if (trimmed.startsWith('<')) throw new ForticloudApiError(`FortiCloud ${label}: the answer is HTML, not JSON (HTTP ${status}).`, status);
  try {
    return JSON.parse(text);
  } catch {
    throw new ForticloudApiError(`FortiCloud ${label}: the response is not JSON (HTTP ${status}).`, status);
  }
}

// --- Tokens ------------------------------------------------------------------------------------

interface CachedToken {
  token: string;
  expiresAt: number;
}

/** Keyed by auth URL, client ID and API ID; the password is never part of a key. */
const tokens = new Map<string, CachedToken>();
const pending = new Map<string, Promise<CachedToken>>();
/** Refused grants, by API ID and auth URL (not portal: a lockout covers every client_id). */
const refused = new Map<string, { until: number; error: ForticloudAuthError }>();

function liveTokens(): string[] {
  return [...tokens.values()].map((t) => t.token);
}

export function clientIdFor(config: ForticloudConfig, portal: Portal): string {
  return portal === 'asset' ? config.assetClientId : config.fgtClientId;
}

async function requestToken(config: ForticloudConfig, portal: Portal): Promise<CachedToken> {
  const client = clientIdFor(config, portal);
  const label = `token for ${PORTAL_NAME[portal]} (client_id ${client})`;
  const body = JSON.stringify({ username: config.apiId, password: config.apiPassword, client_id: client, grant_type: 'password' });
  const { status, text } = await send(config, 'POST', config.authUrl, `POST ${label}`, {}, body, 30_000);
  const parsed = (status >= 200 && status < 300 ? parseJson(text, label, status) : null) as Record<string, unknown> | null;
  const token = typeof parsed?.access_token === 'string' ? parsed.access_token : '';
  if (status === 400 || status === 401 || status === 403 || (status >= 200 && status < 300 && !token)) {
    const detail = errorDetail(text, config);
    const clientHint = /client/i.test(detail)
      ? ` The client_id may be wrong for this portal: set ${CLIENT_ID_ENV[portal]}.`
      : ` The API user's permission profile must give access to ${PORTAL_NAME[portal]}.`;
    throw new ForticloudAuthError(
      `FortiCloud did not issue a ${label} (HTTP ${status})${detail ? `: ${detail}` : ''}.${CREDENTIAL_HINT}${clientHint}`,
      status
    );
  }
  if (status < 200 || status >= 300) {
    const detail = errorDetail(text, config);
    throw new ForticloudApiError(`FortiCloud ${label} failed: HTTP ${status}${detail ? ` - ${detail}` : ''}`, status);
  }
  const seconds = Number(parsed?.expires_in);
  const lifetime = Number.isFinite(seconds) && seconds > 0 ? seconds : DEFAULT_TOKEN_SECONDS;
  logger.debug('FortiCloud token issued', { portal, expiresInSeconds: lifetime });
  return { token, expiresAt: Date.now() + lifetime * 1000 };
}

/** A bearer token for the portal, from the cache while it has more than two minutes left. */
export async function getToken(config: ForticloudConfig, portal: Portal, forceNew = false): Promise<string> {
  const key = `${config.authUrl}|${clientIdFor(config, portal)}|${config.apiId}`;
  const cached = tokens.get(key);
  if (!forceNew && cached && cached.expiresAt - TOKEN_MARGIN_MS > Date.now()) return cached.token;
  const refusedKey = `${config.authUrl}|${config.apiId}`;
  const held = refused.get(refusedKey);
  if (held && held.until > Date.now()) {
    const minutes = Math.ceil((held.until - Date.now()) / 60_000);
    throw new ForticloudAuthError(
      `${held.error.message} No new sign-in is tried for ${minutes} min (repeated failures can lock the API user out).`,
      held.error.httpStatus
    );
  }
  let p = pending.get(key);
  if (!p) {
    p = requestToken(config, portal)
      .catch((err) => {
        if (err instanceof ForticloudAuthError) refused.set(refusedKey, { until: Date.now() + AUTH_FAILURE_HOLD_MS, error: err });
        throw err;
      })
      .finally(() => pending.delete(key));
    pending.set(key, p);
  }
  const fresh = await p;
  tokens.set(key, fresh);
  return fresh.token;
}

/** Seconds left on the cached token for a portal, or undefined. */
export function tokenSecondsLeft(config: ForticloudConfig, portal: Portal): number | undefined {
  const t = tokens.get(`${config.authUrl}|${clientIdFor(config, portal)}|${config.apiId}`);
  return t ? Math.max(0, Math.round((t.expiresAt - Date.now()) / 1000)) : undefined;
}

// --- Portal requests -----------------------------------------------------------------------------

/**
 * A read from a portal with its bearer token. A 401 drops the cached token and
 * tries once with a new one (a token can be revoked before it expires).
 */
export async function portalRequest<T = unknown>(
  config: ForticloudConfig,
  portal: Portal,
  method: 'GET' | 'POST',
  path: string,
  options: { query?: Record<string, string | number | undefined>; body?: unknown } = {}
): Promise<T> {
  const base = portal === 'asset' ? config.assetUrl : config.fgtUrl;
  if (!/^\/[A-Za-z0-9/_.-]*$/.test(path) || path.includes('..')) throw new Error(`Bad API path: ${path}`);
  const url = new URL(`${base}${path}`);
  for (const [k, v] of Object.entries(options.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
  const label = `${method} ${PORTAL_NAME[portal]} ${path}`;
  const body = options.body !== undefined ? JSON.stringify(options.body) : undefined;

  let result: RawResult | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await getToken(config, portal, attempt > 0);
    result = await send(config, method, url.toString(), label, { Authorization: `Bearer ${token}` }, body);
    if (result.status !== 401) break;
  }
  const { status, text } = result as RawResult;
  if (status === 401 || status === 403) {
    const detail = errorDetail(text, config);
    throw new ForticloudAuthError(
      `FortiCloud refused the request (HTTP ${status}): ${label}${detail ? ` - ${detail}` : ''}.` +
        (status === 403 ? ` The API user's permission profile may not include ${PORTAL_NAME[portal]}, or this object.` : CREDENTIAL_HINT),
      status
    );
  }
  if (status === 404) {
    const detail = errorDetail(text, config);
    throw new ForticloudApiError(`FortiCloud ${label}: not found (HTTP 404)${detail ? ` - ${detail}` : ''}`, status);
  }
  if (status < 200 || status >= 300) {
    const detail = errorDetail(text, config);
    throw new ForticloudApiError(`FortiCloud ${label} failed: HTTP ${status}${detail ? ` - ${detail}` : ''}`, status);
  }
  return parseJson(text, label, status) as T;
}

// --- The API handed to tools ------------------------------------------------------------------

/** Asset Management body status codes that are not errors. */
const ASSET_OK = new Set([0]);
/** "No records found": an empty answer, not an error. */
export const ASSET_NO_RECORDS = 1008;

/** Asset Management read endpoints. Every other v3 endpoint writes and is not reachable here. */
const ASSET_READS = new Set(['/products/list', '/products/details', '/contracts/list', '/licenses/list', '/folders/list']);

/** The read-only API handed to tools. */
export interface Api {
  /** POST to an Asset Management read endpoint; body `status` checked (1008 = no records gives `{}` fields empty). */
  asset<T = Record<string, unknown>>(path: string, body: Record<string, unknown>): Promise<T & { status?: number }>;
  /** GET from FortiGate Cloud. */
  fgt<T = unknown>(path: string, query?: Record<string, string | number | undefined>): Promise<T>;
  /** Issues (or reuses) the token for a portal; for the status tool. */
  token(portal: Portal): Promise<{ secondsLeft?: number }>;
  readonly config: Pick<ForticloudConfig, 'assetUrl' | 'fgtUrl' | 'authUrl' | 'assetClientId' | 'fgtClientId'>;
  /** Identifies the API user and endpoints, so caches never cross from one configuration to another. */
  readonly cacheKey: string;
}

export function makeApi(config: ForticloudConfig): Api {
  return {
    config: {
      assetUrl: config.assetUrl,
      fgtUrl: config.fgtUrl,
      authUrl: config.authUrl,
      assetClientId: config.assetClientId,
      fgtClientId: config.fgtClientId,
    },
    cacheKey: [config.authUrl, config.fgtUrl, config.fgtClientId, config.apiId].join('|'),
    async asset<T>(path: string, body: Record<string, unknown>) {
      if (!ASSET_READS.has(path)) throw new Error(`Not an Asset Management read endpoint: ${path}`);
      const out = await portalRequest<Record<string, unknown>>(config, 'asset', 'POST', path, { body });
      const status = typeof out?.status === 'number' ? out.status : Number(out?.status ?? 0);
      if (Number.isFinite(status) && !ASSET_OK.has(status) && status !== ASSET_NO_RECORDS) {
        const detail = errorDetail(JSON.stringify({ message: out.message, error: out.error }), config);
        throw new ForticloudApiError(`FortiCloud Asset Management ${path}: status ${status}${detail ? ` - ${detail}` : ''}`);
      }
      return { ...(out as object), status } as T & { status?: number };
    },
    fgt: (path, query) => portalRequest(config, 'fgt', 'GET', path, { query }),
    async token(portal) {
      await getToken(config, portal);
      return { secondsLeft: tokenSecondsLeft(config, portal) };
    },
  };
}
