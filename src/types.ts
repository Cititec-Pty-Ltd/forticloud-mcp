/**
 * Fortinet FortiCloud, read-only.
 *
 * Two portals, one IAM API user:
 * - Asset Management (support.fortinet.com, API v3): registered products,
 *   their entitlements (support, FortiGuard, FortiCare), contracts and expiry.
 * - FortiGate Cloud (www.forticloud.com, forticloudapi v1): the FortiGates
 *   managed from FortiGate Cloud, their connection to it, firmware and config
 *   backups.
 *
 * Authentication: FortiCloud IAM. The API user's ID and password are exchanged
 * at customerapiauth.fortinet.com for an OAuth bearer token, one per portal
 * (each portal has its own client_id). Tokens are cached until shortly before
 * they expire.
 */
export interface ForticloudConfig {
  apiId: string;
  apiPassword: string;
  /** OAuth token endpoint (full URL). */
  authUrl: string;
  /** Asset Management API base, ending in /v3 (no trailing slash). */
  assetUrl: string;
  /** FortiGate Cloud API base (no trailing slash). */
  fgtUrl: string;
  assetClientId: string;
  fgtClientId: string;
  /**
   * IANA time zone that calendar dates are shown in (end dates, windows).
   * daysLeft does not depend on it: it counts 24-hour periods to the exact expiry.
   */
  timeZone: string;
}

export type Portal = 'asset' | 'fgt';

/** FortiCloud refused the credentials or the token (401/403, or an auth error in the body). */
export class ForticloudAuthError extends Error {
  constructor(
    message: string,
    readonly httpStatus?: number
  ) {
    super(message);
  }
}

/** FortiCloud rate-limited the request (HTTP 429, or 503 with a wait). */
export class ForticloudRateLimitError extends Error {
  readonly code = 'rate_limited';
  constructor(
    message: string,
    readonly retryAfterSeconds: number
  ) {
    super(message);
  }
}

/** Any other failure: a non-2xx response, a network error, an unreadable body. */
export class ForticloudApiError extends Error {
  constructor(
    message: string,
    readonly httpStatus?: number
  ) {
    super(message);
  }
}
