import type { Api } from '../client.js';
import { displayTimeZone } from '../client.js';
import { ForticloudRateLimitError } from '../types.js';
import { InputError, clean, compact, num } from './shared.js';

type Raw = Record<string, unknown>;

const DAY_MS = 86_400_000;

// --- Values ------------------------------------------------------------------------------------

/**
 * A FortiCloud date as epoch ms. Asset Management writes ISO 8601 with offsets
 * like "-8:00" (one-digit hour), which Date.parse rejects, so the offset is
 * padded first. Numbers are epoch seconds (or ms when that large). 0 is none.
 */
/**
 * A date with no time zone: "2030-01-01" or "2030-01-01T00:00:00[.000]". It is
 * a calendar date: day() shows it as written, parseDate() reads it as UTC.
 */
export const ZONELESS_DATE = /^\d{4}-\d\d-\d\d(T\d\d:\d\d(:\d\d(\.\d+)?)?)?$/;

export function parseDate(value: unknown): number | undefined {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) return undefined;
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const s = value.trim().replace(/([+-])(\d):(\d\d)$/, '$10$2:$3');
  if (/^\d+$/.test(s)) return parseDate(Number(s));
  // No zone given ("2030-01-01T00:00:00"): read as UTC, not as this machine's local time.
  const zoned = ZONELESS_DATE.test(s) ? (s.length === 10 ? `${s}T00:00:00Z` : `${s}Z`) : s;
  const ms = Date.parse(zoned);
  return Number.isNaN(ms) ? undefined : ms;
}

/**
 * The calendar date (YYYY-MM-DD) of a FortiCloud date, for display.
 *
 * Time-zone rule (the same for every tool):
 * - a date with an offset ("...-8:00", "...Z") or an epoch number is a moment,
 *   shown as the date it falls on in FORTICLOUD_TIME_ZONE (default UTC; the
 *   Cititec host uses Australia/Melbourne);
 * - a date with no zone ("2030-01-01T00:00:00") is a calendar date and is shown
 *   as written.
 * daysLeft never depends on the time zone; see daysLeft.
 */
export function day(value: unknown, timeZone: string = displayTimeZone()): string | undefined {
  if (typeof value === 'string' && ZONELESS_DATE.test(value.trim())) return value.trim().slice(0, 10);
  const ms = parseDate(value);
  if (ms === undefined) return undefined;
  // en-CA formats as YYYY-MM-DD.
  return new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(ms);
}

/** ISO date-time (UTC, seconds) of a FortiCloud date. */
export function stamp(value: unknown): string | undefined {
  const ms = parseDate(value);
  return ms === undefined ? undefined : new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Whole 24-hour periods from `now` to the exact expiry moment, rounded down:
 * 0 = ends within the next 24 hours (later today included), negative = has
 * ended (-1 = within the last 24 hours). Computed from the original timestamp,
 * never from a displayed date, so it does not depend on any time zone.
 */
export function daysLeft(value: unknown, now = Date.now()): number | undefined {
  const ms = parseDate(value);
  return ms === undefined ? undefined : Math.floor((ms - now) / DAY_MS);
}

/**
 * The expiry of something with one or more end dates (an entitlement, a
 * contract and its terms, a licence): the latest moment among `values`, with
 * its display date and daysLeft both taken from that original value. Every
 * tool uses this, so contracts and entitlements always agree.
 */
export function expiryOf(values: unknown[], now = Date.now()): { end?: string; daysLeft?: number } {
  const best = latestMoment(values);
  return best ? { end: day(best.value), daysLeft: daysLeft(best.value, now) } : {};
}

/**
 * The latest of `values` by exact parsed moment (never by a rounded day or by
 * date text), with that original value; undefined when none parses. Ties keep
 * the first, which only happens for identical moments, so order never matters.
 */
export function latestMoment(values: unknown[]): { value: unknown; ms: number } | undefined {
  let best: { value: unknown; ms: number } | undefined;
  for (const value of values) {
    const ms = parseDate(value);
    if (ms !== undefined && (!best || ms > best.ms)) best = { value, ms };
  }
  return best;
}

/** Sorts by exact moment, soonest first; items with no moment last. */
export const byMoment = (a: { ms?: number }, b: { ms?: number }): number => (a.ms ?? Infinity) - (b.ms ?? Infinity);

/** The cut-off date Asset Management's expireBefore takes, `days` from now. */
export function expireBefore(days: number, now = Date.now()): string {
  return `${new Date(now + days * DAY_MS).toISOString().slice(0, 10)}T23:59:59+00:00`;
}

/**
 * A FortiCloud flag in any of the forms seen: true/false, "true"/"false",
 * 1/0, "1"/"0", "yes"/"no" (any case). Anything else is unknown. Every flag a
 * tool shows or filters on goes through this (in assetRow and deviceRow), never
 * a raw === true.
 */
export function bool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (v === 1 || v === 0) return v === 1;
  if (typeof v !== 'string') return undefined;
  const s = v.trim().toLowerCase();
  if (s === 'true' || s === '1' || s === 'yes') return true;
  if (s === 'false' || s === '0' || s === 'no') return false;
  return undefined;
}

/** A FortiCloud serial number: letters, digits and dashes. Used in paths, so strict. */
export function checkSerial(value: unknown, key = 'serial'): string {
  const s = typeof value === 'string' ? value.trim().toUpperCase() : '';
  if (!/^[A-Z0-9-]{4,40}$/.test(s)) throw new InputError(`${key} must be a serial number (letters, digits and dashes)`);
  return s;
}

/** A serial-number pattern for Asset Management (it matches serials that start with it). */
export function checkSerialPattern(value: unknown, key = 'serial_prefix'): string {
  const s = typeof value === 'string' ? value.trim().toUpperCase() : '';
  if (!/^[A-Z0-9-]{1,40}$/.test(s)) throw new InputError(`${key} must be letters, digits and dashes`);
  return s;
}

/**
 * Generic, bounded copy of an object of unknown shape: strings cleaned and
 * cut, nested objects kept to `depth`, arrays to `maxItems`. For fields whose
 * exact shape is not documented publicly.
 */
export function tidy(value: unknown, depth = 3, maxItems = 50): unknown {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') return clean(value, 300);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth <= 0) return undefined;
  if (Array.isArray(value)) {
    const items = value.slice(0, maxItems).map((v) => tidy(v, depth - 1, maxItems)).filter((v) => v !== undefined);
    return items.length ? items : undefined;
  }
  if (typeof value === 'object') {
    const out: Raw = {};
    for (const [k, v] of Object.entries(value as Raw).slice(0, 80)) {
      const t = tidy(v, depth - 1, maxItems);
      if (t !== undefined && t !== '') out[k] = t;
    }
    return Object.keys(out).length ? out : undefined;
  }
  return undefined;
}

/** Contains, ignoring case. */
export const has = (hay: unknown, needle: string | undefined): boolean =>
  needle === undefined || (typeof hay === 'string' && hay.toLowerCase().includes(needle.toLowerCase()));

/** A page of an in-memory list, with the paging fields every list returns. */
export function pageOf<T>(items: T[], limit: number, offset: number) {
  const slice = items.slice(offset, offset + limit);
  return {
    total: items.length,
    count: slice.length,
    offset,
    ...(offset + slice.length < items.length ? { nextOffset: offset + slice.length } : {}),
    items: slice,
  };
}

// --- FortiGate Cloud devices ---------------------------------------------------------------------

/** Field names seen or expected for a "last seen" time; the public docs show none. */
const LAST_SEEN_FIELDS = [
  'lastSeen', 'lastSeenTime', 'lastConnectTime', 'lastConnectedTime', 'lastConnected', 'lastUpdateTime',
  'lastUpdate', 'lastHeartbeat', 'lastLogTime', 'lastLoginTime',
];
/** Field names that may carry a connection state as text. */
const CONNECTION_FIELDS = ['connectionStatus', 'connectStatus', 'connStatus', 'tunnelStatus', 'managementStatus'];

export type Connection = 'online' | 'offline' | 'unknown';

/**
 * Whether the FortiGate's management tunnel to FortiGate Cloud is up. The
 * documented field is `tunnelAlive`; a text status field, if the API returns
 * one, is passed on as `connectionDetail`.
 */
export function connectionOf(d: Raw): { connection: Connection; connectionDetail?: string } {
  const detail = CONNECTION_FIELDS.map((k) => clean(d[k], 40)).find(Boolean);
  const alive = bool(d.tunnelAlive);
  let connection: Connection = alive === true ? 'online' : alive === false ? 'offline' : 'unknown';
  if (connection === 'unknown' && detail) {
    if (/^(up|online|connected|good|ok|alive)$/i.test(detail)) connection = 'online';
    else if (/^(down|offline|disconnected|lost|dead)$/i.test(detail)) connection = 'offline';
  }
  return { connection, ...(detail ? { connectionDetail: detail } : {}) };
}

export function lastSeenOf(d: Raw): string | undefined {
  for (const k of LAST_SEEN_FIELDS) {
    const s = stamp(d[k]);
    if (s) return s;
  }
  return undefined;
}

/**
 * A device's serial, upper case, from whichever field FortiGate Cloud uses
 * (`sn` in the documented sample; `serialNumber` or `serial` elsewhere);
 * '' when there is none. Every lookup and de-duplication goes through this.
 */
export function serialOf(d: Raw): string {
  for (const v of [d.sn, d.serialNumber, d.serial]) {
    if (typeof v === 'string' && v.trim()) return v.trim().toUpperCase();
    if (typeof v === 'number') return String(v);
  }
  return '';
}

export interface DeviceRow {
  serial: string;
  name?: string;
  model?: string;
  firmware?: string;
  connection: Connection;
  connectionDetail?: string;
  lastSeen?: string;
  account?: string;
  accountId?: number;
  managedByFortiGateCloud?: boolean;
  fortigateCloudContractEnd?: string;
  trial?: boolean;
}

/** One device from FortiGate Cloud's /devices, trimmed to the useful fields. */
export function deviceRow(d: Raw, accounts?: Map<number, string>): DeviceRow {
  const accountId = num(d.subAccountOid ?? d.subAccountId ?? d.accountId);
  return compact({
    serial: clean(serialOf(d), 40) ?? '?',
    name: clean(d.name ?? d.hostname ?? d.hostName, 120),
    model: clean(d.model ?? d.platform, 60),
    firmware: clean(d.firmwareVersion ?? d.firmware ?? d.version, 40),
    ...connectionOf(d),
    lastSeen: lastSeenOf(d),
    account: accountId !== undefined ? (accounts?.get(accountId) ?? (accountId === -1 ? '<Default>' : undefined)) : undefined,
    accountId,
    managedByFortiGateCloud: bool(d.management),
    fortigateCloudContractEnd: day(d.contractEndTime),
    trial: bool(d.trial),
  }) as DeviceRow;
}

/** The array in a FortiGate Cloud list answer: a bare array, or one under data/devices/items/result. */
export function listOf(body: unknown): Raw[] {
  if (Array.isArray(body)) return body.filter((x): x is Raw => !!x && typeof x === 'object');
  if (body && typeof body === 'object') {
    for (const k of ['data', 'devices', 'items', 'result', 'results', 'subaccounts']) {
      const v = (body as Raw)[k];
      if (Array.isArray(v)) return listOf(v);
    }
  }
  return [];
}

const DEVICE_PAGE = 500;
const MAX_DEVICE_PAGES = 10;
const CACHE_MS = 60_000;
const ACCOUNT_CACHE_MS = 5 * 60_000;

const deviceCache = new Map<string, { at: number; value: Promise<{ devices: Raw[]; complete: boolean }> }>();
const accountCache = new Map<string, { at: number; value: Promise<Map<number, string> | null> }>();

export function clearCaches(): void {
  deviceCache.clear();
  accountCache.clear();
}

/**
 * Every FortiGate in FortiGate Cloud. /devices is paged with limit and offset
 * (as open-source clients use it); the loop stops on a short page, when a page
 * adds no new serial (paging ignored), at the `total` the items carry, or
 * after ten pages. `complete` is true only when a short page or `total` shows
 * the whole fleet was read. Cached for a minute, so one conversation's lookups make one
 * request.
 */
export function allDevices(api: Api): Promise<{ devices: Raw[]; complete: boolean }> {
  const key = api.cacheKey;
  const hit = deviceCache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  const value = (async () => {
    const seen = new Map<string, Raw>();
    let complete = false;
    // The largest total any page advertised: a later empty or short page carries none, and must not erase it.
    let total: number | undefined;
    for (let page = 0; page < MAX_DEVICE_PAGES; page++) {
      const items = listOf(await api.fgt('/devices', { limit: DEVICE_PAGE, offset: page * DEVICE_PAGE }));
      const before = seen.size;
      for (const d of items) {
        const sn = serialOf(d);
        if (sn && !seen.has(sn)) seen.set(sn, d);
        const t = num(d.total);
        if (t !== undefined) total = Math.max(total ?? 0, t);
      }
      if (total !== undefined && seen.size >= total) {
        complete = true;
        break;
      }
      if (items.length < DEVICE_PAGE) {
        // The last page; it is the whole fleet unless the items say there are more.
        complete = total === undefined || seen.size >= total;
        break;
      }
      if (seen.size === before) break; // offset ignored: a repeated full page proves nothing about the rest
    }
    return { devices: [...seen.values()], complete };
  })();
  deviceCache.set(key, { at: Date.now(), value });
  value.catch(() => deviceCache.delete(key));
  return value;
}

/**
 * FortiGate Cloud sub-accounts (an MSSP's client accounts) by ID; null when the
 * API refuses. A rate limit is never turned into null: it is thrown, so the
 * call stops and reports the wait, and it is not cached.
 */
export function accountNames(api: Api): Promise<Map<number, string> | null> {
  const key = api.cacheKey;
  const hit = accountCache.get(key);
  if (hit && Date.now() - hit.at < ACCOUNT_CACHE_MS) return hit.value;
  const value = api
    .fgt('/subaccounts')
    .then((body) => {
      const map = new Map<number, string>();
      for (const a of listOf(body)) {
        const id = num(a.oid ?? a.id ?? a.accountId);
        const name = clean(a.name ?? a.accountName, 120);
        if (id !== undefined && name) map.set(id, name);
      }
      return map;
    })
    .catch((err) => {
      if (err instanceof ForticloudRateLimitError) throw err;
      return null;
    });
  accountCache.set(key, { at: Date.now(), value });
  value.catch(() => accountCache.delete(key));
  return value;
}

/** Sub-accounts with their parent, for forticloud_list_accounts. */
export function accountRows(body: unknown) {
  return listOf(body).map((a) =>
    compact({ accountId: num(a.oid ?? a.id ?? a.accountId), name: clean(a.name ?? a.accountName, 120), parentId: num(a.parent ?? a.parentId) })
  );
}

/** Compares firmware strings like "7.2.8" or "v7.4.3,build2573" numerically; unknown last. */
export function compareFirmware(a: string | undefined, b: string | undefined): number {
  const parts = (s: string | undefined) => (s?.match(/\d+/g) ?? []).slice(0, 4).map(Number);
  const pa = parts(a);
  const pb = parts(b);
  if (!pa.length || !pb.length) return pa.length ? -1 : pb.length ? 1 : 0;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

// --- Asset Management ------------------------------------------------------------------------------

export interface EntitlementRow {
  type?: string;
  level?: string;
  start?: string;
  end?: string;
  daysLeft?: number;
}

const endOf = (e: Raw): unknown => e.endDate ?? e.expirationDate ?? e.experiationDate;

export function entitlementRow(e: Raw, now = Date.now()): EntitlementRow {
  return compact({
    type: clean(e.typeDesc ?? e.type, 80),
    level: clean(e.levelDesc ?? e.level, 60),
    start: day(e.startDate),
    ...expiryOf([endOf(e)], now),
  }) as EntitlementRow;
}

/**
 * The latest entitlement of each type, each with its exact end moment (`ms`),
 * soonest first. A renewed service keeps its old, ended entitlement next to the
 * new one; only the latest counts. "Latest" is by exact moment, so two ends in
 * the same 24 hours are told apart and the API's order does not matter; the
 * display date and daysLeft then come from that one entitlement.
 */
export function latestEntitlements(entitlements: unknown, now = Date.now()): { row: EntitlementRow; ms?: number }[] {
  const best = new Map<string, { row: EntitlementRow; ms?: number }>();
  for (const e of Array.isArray(entitlements) ? entitlements : []) {
    if (!e || typeof e !== 'object') continue;
    const row = entitlementRow(e as Raw, now);
    const ms = parseDate(endOf(e as Raw));
    const key = row.type ?? '?';
    const cur = best.get(key);
    if (!cur || (ms ?? -Infinity) > (cur.ms ?? -Infinity)) best.set(key, { row, ms });
  }
  return [...best.values()].sort(byMoment);
}

/** latestEntitlements without the moments, for output. */
export function latestByType(entitlements: unknown, now = Date.now()): EntitlementRow[] {
  return latestEntitlements(entitlements, now).map((x) => x.row);
}

/**
 * One asset (registered product) from products/list or products/details, trimmed.
 * nextExpiry: the soonest end still ahead (by exact moment). supportEnd: the
 * latest end among the support-type entitlements (Support, FortiCare), by
 * exact moment.
 */
export function assetRow(a: Raw, now = Date.now()) {
  const latest = latestEntitlements(a.entitlements, now);
  const ents = latest.map((x) => x.row);
  const future = latest.filter((x) => x.ms !== undefined && x.ms >= now).map((x) => x.row);
  const supports = latest.filter((x) => /support|forticare/i.test(x.row.type ?? ''));
  const support = supports.reduce<(typeof supports)[number] | undefined>(
    (best, x) => (!best || (x.ms ?? -Infinity) > (best.ms ?? -Infinity) ? x : best),
    undefined
  )?.row;
  return compact({
    serial: clean(a.serialNumber, 40) ?? '?',
    model: clean(a.productModel, 80),
    description: clean(a.description, 200),
    folder: clean(a.folderPath ?? a.folderName, 200),
    accountId: num(a.accountId),
    status: clean(a.status, 40),
    registered: day(a.registrationDate),
    decommissioned: bool(a.isDecommissioned),
    endOfOrder: day(a.productModelEoR),
    endOfSupport: day(a.productModelEoS),
    supportEnd: support?.end,
    nextExpiry: future[0] ? compact({ type: future[0].type, end: future[0].end, daysLeft: future[0].daysLeft }) : undefined,
    entitlements: ents.length ? ents : undefined,
  });
}

/** The asset array in a products/list answer (null when there are none). */
export function assetsOf(body: Raw): Raw[] {
  const v = body.assets ?? body.products;
  return Array.isArray(v) ? v.filter((x): x is Raw => !!x && typeof x === 'object') : [];
}
