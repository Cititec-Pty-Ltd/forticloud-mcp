import type { Api } from '../client.js';
import { ASSET_NO_RECORDS } from '../client.js';
import {
  accountNames,
  accountRows,
  allDevices,
  assetRow,
  assetsOf,
  checkSerial,
  checkSerialPattern,
  compareFirmware,
  day,
  daysLeft,
  deviceRow,
  entitlementRow,
  expireBefore,
  has,
  latestByType,
  listOf,
  pageOf,
  serialOf,
  tidy,
} from './format.js';
import type { DeviceRow } from './format.js';
import { InputError, clean, compact, num } from './shared.js';
import type { ParamSpec, ToolSpec } from './spec.js';

type Raw = Record<string, unknown>;

// --- Common parameters ---------------------------------------------------------------------

const limit = (dflt: number, max = 200): ParamSpec => ({
  type: 'int',
  description: `Rows to return (1-${max}).`,
  min: 1,
  max,
  default: dflt,
});
const offset: ParamSpec = {
  type: 'int',
  description: 'Rows to skip, for the next page (use nextOffset from the previous result).',
  min: 0,
  max: 100_000,
  default: 0,
};
const serial: ParamSpec = { type: 'string', description: 'The serial number, e.g. FGT60FTK00000000.', required: true, maxLength: 40 };
const account: ParamSpec = {
  type: 'string',
  description:
    'Only devices of this FortiGate Cloud sub-account (a client, for an MSSP account): its name (contains, any case) or its numeric ID from forticloud_list_accounts.',
  maxLength: 100,
};

const str = (v: unknown) => v as string | undefined;
const int = (v: unknown) => v as number | undefined;

/** Largest number of Asset Management pages (25 assets each) one call reads. */
const MAX_ASSET_PAGES = 12;

/** Errors from one part of a result, kept short; the rest of the result still stands. */
const partError = (err: unknown) => clean((err as Error).message, 300) ?? 'failed';

// --- FortiGate Cloud ---------------------------------------------------------------------------

/** Said whenever a result rests on a device list that FortiGate Cloud did not return in full. */
export const INCOMPLETE_WARNING =
  'FortiGate Cloud did not return the whole device list (paging stopped before its advertised total, or after 10 pages), ' +
  'so this result covers only part of the fleet. Do not present it as complete; narrow the question (an account or a name) or report the gap.';

/** Every tool built on allDevices spreads this into its result, so a partial inventory is never shown as a full one. */
export function completeness(complete: boolean): { complete?: false; warning?: string } {
  return complete ? {} : { complete: false, warning: INCOMPLETE_WARNING };
}

async function devicesWithAccounts(api: Api) {
  const [{ devices, complete }, accounts] = await Promise.all([allDevices(api), accountNames(api)]);
  return { rows: devices.map((d) => deviceRow(d, accounts ?? undefined)), complete, accounts };
}

function matchAccount(row: DeviceRow, wanted: string | undefined): boolean {
  if (wanted === undefined) return true;
  if (/^-?\d+$/.test(wanted)) return row.accountId === Number(wanted);
  return has(row.account, wanted);
}

function connectionCounts(rows: DeviceRow[]) {
  const counts = { online: 0, offline: 0, unknown: 0 };
  for (const r of rows) counts[r.connection]++;
  return counts;
}

async function status(api: Api) {
  const fgt = (async () => {
    const token = await api.token('fgt');
    const { devices, complete } = await allDevices(api);
    const rows = devices.map((d) => deviceRow(d));
    return compact({ ok: true, tokenSecondsLeft: token.secondsLeft, devices: rows.length, ...completeness(complete), ...connectionCounts(rows) });
  })().catch((err) => ({ ok: false, error: partError(err) }));
  // Asset Management allows only 10 errors an hour, so its check is the cheapest read there is.
  const asset = (async () => {
    const token = await api.token('asset');
    const body = await api.asset('/folders/list', {});
    const folders = Array.isArray(body.folders) ? body.folders.length : undefined;
    return compact({ ok: true, tokenSecondsLeft: token.secondsLeft, folders });
  })().catch((err) => ({ ok: false, error: partError(err) }));
  const [fortigateCloud, assetManagement] = await Promise.all([fgt, asset]);
  return {
    fortigateCloud: { url: api.config.fgtUrl, clientId: api.config.fgtClientId, ...fortigateCloud },
    assetManagement: { url: api.config.assetUrl, clientId: api.config.assetClientId, ...assetManagement },
    tokenUrl: api.config.authUrl,
  };
}

async function listAccounts(args: Raw, api: Api) {
  const [body, inventory] = await Promise.all([
    api.fgt('/subaccounts'),
    devicesWithAccounts(api).catch((err) => ({ rows: [] as DeviceRow[], complete: false, error: partError(err) })),
  ]);
  const rows = inventory.rows;
  const counts = new Map<number, { devices: number; offline: number }>();
  for (const r of rows) {
    if (r.accountId === undefined) continue;
    const c = counts.get(r.accountId) ?? { devices: 0, offline: 0 };
    c.devices++;
    if (r.connection === 'offline') c.offline++;
    counts.set(r.accountId, c);
  }
  const accounts = accountRows(body)
    .filter((a) => has(a.name, str(args.name)))
    .map((a) => ({ ...a, ...(a.accountId !== undefined ? counts.get(a.accountId) : undefined) }))
    .sort((a, b) => String(a.name ?? '').localeCompare(String(b.name ?? '')));
  const { items, ...paging } = pageOf(accounts, int(args.limit)!, int(args.offset)!);
  const deviceError = 'error' in inventory ? inventory.error : undefined;
  return compact({
    ...paging,
    ...(deviceError
      ? { complete: false, warning: `Device counts are missing: the device list could not be read (${deviceError}).` }
      : completeness(inventory.complete)),
    accounts: items,
  });
}

async function listDevices(args: Raw, api: Api) {
  const { rows, complete, accounts } = await devicesWithAccounts(api);
  const wanted = str(args.connection);
  const filtered = rows
    .filter((r) => matchAccount(r, str(args.account)))
    .filter((r) => !wanted || r.connection === wanted)
    .filter((r) => has(r.model, str(args.model)))
    .filter((r) => has(r.firmware, str(args.firmware)))
    .filter((r) => str(args.name) === undefined || has(r.name, str(args.name)) || has(r.serial, str(args.name)))
    .sort(
      (a, b) =>
        (a.connection === 'offline' ? 0 : 1) - (b.connection === 'offline' ? 0 : 1) ||
        String(a.account ?? '').localeCompare(String(b.account ?? '')) ||
        String(a.name ?? a.serial).localeCompare(String(b.name ?? b.serial))
    );
  const { items, ...paging } = pageOf(filtered, int(args.limit)!, int(args.offset)!);
  return compact({
    ...paging,
    matching: connectionCounts(filtered),
    ...completeness(complete),
    note: accounts === null && str(args.account) !== undefined ? 'Sub-account names could not be read; filter by the numeric account ID.' : undefined,
    devices: items,
  });
}

/** Scalar fields of a raw device that the trimmed row does not already show (to see what the API returns). */
function extraFields(d: Raw): Raw | undefined {
  const shown = new Set([
    'sn', 'serialNumber', 'name', 'model', 'firmwareVersion', 'tunnelAlive', 'subAccountOid', 'management',
    'contractEndTime', 'trial', 'total', 'latitude', 'longitude', 'ip',
  ]);
  const out: Raw = {};
  for (const [k, v] of Object.entries(d)) {
    if (shown.has(k) || v === null || v === '' || typeof v === 'object') continue;
    out[k] = typeof v === 'string' ? clean(v, 200) : v;
  }
  return Object.keys(out).length ? out : undefined;
}

async function getDevice(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const accounts = await accountNames(api);
  let raw: Raw | undefined;
  try {
    const body = await api.fgt(`/devices/${sn}`);
    raw = (Array.isArray(body) ? body[0] : (body as Raw)?.data ?? body) as Raw;
  } catch (err) {
    // Some accounts answer the list but not the single device; fall back to the list.
    const { devices, complete } = await allDevices(api);
    raw = devices.find((d) => serialOf(d) === sn);
    if (!raw) {
      if (complete) throw err;
      throw new Error(`${(err as Error).message} It is not in the device list either, but that list is incomplete: ${INCOMPLETE_WARNING}`);
    }
  }
  const [backup, asset] = await Promise.all([
    api.fgt(`/devices/${sn}/configbackups/setting`).then(
      (b) => tidy(b),
      (err) => ({ error: partError(err) })
    ),
    args.include_asset
      ? api.asset('/products/details', { serialNumber: sn }).then(
          (b) => {
            const d = (b.assetDetails ?? b.asset ?? b) as Raw;
            return d.serialNumber ? assetRow(d) : { error: 'not found in Asset Management' };
          },
          (err) => ({ error: partError(err) })
        )
      : Promise.resolve(undefined),
  ]);
  return compact({
    ...deviceRow(raw ?? {}, accounts ?? undefined),
    otherFields: extraFields(raw ?? {}),
    configBackupSettings: backup,
    assetManagement: asset,
  });
}

async function firmwareSummary(args: Raw, api: Api) {
  const { rows, complete } = await devicesWithAccounts(api);
  const filtered = rows.filter((r) => matchAccount(r, str(args.account))).filter((r) => has(r.model, str(args.model)));
  const groups = new Map<string, DeviceRow[]>();
  for (const r of filtered) {
    const v = r.firmware ?? 'unknown';
    groups.set(v, [...(groups.get(v) ?? []), r]);
  }
  const versions = [...groups.entries()]
    .sort(([a], [b]) => compareFirmware(a === 'unknown' ? undefined : a, b === 'unknown' ? undefined : b))
    .map(([version, devs]) => {
      const models: Record<string, number> = {};
      for (const d of devs) models[d.model ?? '?'] = (models[d.model ?? '?'] ?? 0) + 1;
      return compact({
        version,
        devices: devs.length,
        offline: devs.filter((d) => d.connection === 'offline').length || undefined,
        models,
        list: args.list_devices ? devs.slice(0, 100).map((d) => compact({ serial: d.serial, name: d.name, account: d.account })) : undefined,
      });
    });
  const majors: Record<string, number> = {};
  for (const r of filtered) {
    const m = r.firmware?.match(/\d+\.\d+/)?.[0] ?? 'unknown';
    majors[m] = (majors[m] ?? 0) + 1;
  }
  return compact({ devices: filtered.length, ...completeness(complete), byMajorVersion: majors, versions });
}

async function configBackupStatus(args: Raw, api: Api) {
  let targets: DeviceRow[];
  let total: number;
  let next: number | undefined;
  // One serial is read directly, so the list's completeness does not matter there.
  let complete = true;
  if (str(args.serial) !== undefined) {
    const sn = checkSerial(args.serial);
    const { rows } = await devicesWithAccounts(api).catch(() => ({ rows: [] as DeviceRow[] }));
    targets = [rows.find((r) => r.serial.toUpperCase() === sn) ?? { serial: sn, connection: 'unknown' }];
    total = 1;
  } else {
    const inventory = await devicesWithAccounts(api);
    complete = inventory.complete;
    const all = inventory.rows.filter((r) => matchAccount(r, str(args.account))).sort((a, b) => String(a.name ?? a.serial).localeCompare(String(b.name ?? b.serial)));
    const page = pageOf(all, int(args.limit)!, int(args.offset)!);
    targets = page.items;
    total = page.total;
    next = page.nextOffset;
  }
  // FortiGate Cloud allows few errors a minute: stop asking after three failures.
  let failures = 0;
  const results = [];
  for (const d of targets) {
    if (failures >= 3) {
      results.push(compact({ serial: d.serial, name: d.name, skipped: 'stopped after three errors' }));
      continue;
    }
    try {
      const body = await api.fgt(`/devices/${d.serial}/configbackups/setting`);
      results.push(compact({ serial: d.serial, name: d.name, account: d.account, connection: d.connection, settings: tidy(body) }));
    } catch (err) {
      failures++;
      results.push(compact({ serial: d.serial, name: d.name, account: d.account, error: partError(err) }));
    }
  }
  return compact({
    total,
    count: results.length,
    nextOffset: next,
    ...completeness(complete),
    note: 'FortiGate Cloud publishes the automatic backup settings per device; it has no documented list of backup revisions.',
    devices: results,
  });
}

// --- Asset Management ------------------------------------------------------------------------------

/** Reads products/list pages 1..maxPages (25 assets a page). */
async function assetPages(api: Api, body: Raw, firstPage: number, maxPages: number) {
  const assets: Raw[] = [];
  let totalPages: number | undefined;
  let page = firstPage;
  for (; page < firstPage + maxPages; page++) {
    const res = await api.asset('/products/list', { ...body, pageNumber: page });
    if (res.status === ASSET_NO_RECORDS) {
      totalPages ??= page - 1;
      break;
    }
    assets.push(...assetsOf(res));
    totalPages = num(res.totalPages) ?? totalPages;
    if (totalPages === undefined || page >= totalPages || assetsOf(res).length === 0) break;
  }
  const lastRead = Math.min(page, firstPage + maxPages - 1);
  const complete = totalPages === undefined || lastRead >= totalPages;
  return { assets, totalPages, lastPageRead: lastRead, complete };
}

async function listAssets(args: Raw, api: Api) {
  const prefix = checkSerialPattern(args.serial_prefix);
  const pages = int(args.pages)!;
  const r = await assetPages(api, { serialNumber: prefix }, int(args.page)!, pages);
  const rows = r.assets
    .map((a) => assetRow(a))
    .filter((a) => args.include_decommissioned || a.decommissioned !== true)
    .filter((a) => has(a.model, str(args.model)))
    .filter((a) => has(a.folder, str(args.folder)))
    .map(({ entitlements, ...rest }) => rest);
  return compact({
    serialPrefix: prefix,
    pagesRead: `${args.page}-${r.lastPageRead}`,
    totalPages: r.totalPages,
    nextPage: r.complete ? undefined : r.lastPageRead + 1,
    count: rows.length,
    assets: rows,
  });
}

async function getAsset(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const body = await api.asset('/products/details', { serialNumber: sn });
  const d = (body.assetDetails ?? body.asset ?? {}) as Raw;
  if (body.status === ASSET_NO_RECORDS || !d.serialNumber) throw new InputError(`Asset Management has no product ${sn} that this API user can read`);
  const now = Date.now();
  const contracts = (Array.isArray(d.contracts) ? d.contracts : []).slice(0, 50).map((c: Raw) =>
    compact({
      contract: clean(c.contractNumber, 60),
      sku: clean(c.sku ?? c.contractSKU, 80),
      terms: (Array.isArray(c.terms) ? c.terms : []).slice(0, 20).map((t: Raw) =>
        compact({ supportType: clean(t.supportType, 80), start: day(t.startDate), end: day(t.endDate), daysLeft: daysLeft(t.endDate, now) })
      ),
    })
  );
  const licenses = (Array.isArray(d.licenses) ? d.licenses : d.license ? [d.license] : []).slice(0, 50).map((l: Raw) =>
    compact({ license: clean(l.licenseNumber, 60), sku: clean(l.licenseSKU ?? l.sku, 80), status: clean(l.status, 40), end: day(l.expirationDate ?? l.endDate) })
  );
  return compact({
    ...assetRow(d, now),
    allEntitlements: (Array.isArray(d.entitlements) ? d.entitlements : []).slice(0, 100).map((e: Raw) => entitlementRow(e, now)),
    contracts: contracts.length ? contracts : undefined,
    licenses: licenses.length ? licenses : undefined,
    warranty: tidy(d.warrantySupports, 3, 20),
    location: tidy(d.location, 2),
    partner: tidy(d.partner, 2),
  });
}

async function listExpiring(args: Raw, api: Api) {
  const days = int(args.days)!;
  const expiredDays = int(args.include_expired_days) ?? 0;
  const now = Date.now();
  const body: Raw = { expireBefore: expireBefore(days, now) };
  if (str(args.serial_prefix) !== undefined) body.serialNumber = checkSerialPattern(args.serial_prefix);
  const r = await assetPages(api, body, 1, MAX_ASSET_PAGES);
  const rows = [];
  const assetsWithExpiry = new Set<string>();
  for (const a of r.assets) {
    if (a.isDecommissioned === true && !args.include_decommissioned) continue;
    const asset = assetRow(a, now);
    if (!has(asset.folder, str(args.folder))) continue;
    for (const e of latestByType(a.entitlements, now)) {
      if (e.daysLeft === undefined || e.daysLeft > days || e.daysLeft < -expiredDays) continue;
      if (!has(e.type, str(args.type))) continue;
      assetsWithExpiry.add(asset.serial ?? "?");
      rows.push(compact({ serial: asset.serial, model: asset.model, description: asset.description, folder: asset.folder, ...e }));
    }
  }
  rows.sort((a, b) => (a.daysLeft ?? 0) - (b.daysLeft ?? 0));
  const byType: Record<string, number> = {};
  for (const row of rows) byType[row.type ?? '?'] = (byType[row.type ?? '?'] ?? 0) + 1;
  const { items, ...paging } = pageOf(rows, int(args.limit)!, int(args.offset)!);
  return compact({
    window: compact({ from: expiredDays ? day(now - expiredDays * 86_400_000) : day(now), to: day(now + days * 86_400_000) }),
    assets: assetsWithExpiry.size,
    byType,
    complete: r.complete ? undefined : false,
    note: r.complete
      ? undefined
      : `Only the first ${MAX_ASSET_PAGES * 25} assets were read; narrow with serial_prefix (e.g. FG for FortiGates) or fewer days.`,
    ...paging,
    entitlements: items,
  });
}

async function listContracts(args: Raw, api: Api) {
  const body: Raw = {};
  if (str(args.status) !== undefined) body.status = str(args.status);
  if (str(args.contract_number) !== undefined) {
    const c = str(args.contract_number)!;
    if (!/^[A-Za-z0-9-]{3,40}$/.test(c)) throw new InputError('contract_number must be letters, digits and dashes');
    body.contractNumber = c;
  }
  const res = await api.asset('/contracts/list', body);
  const list = Array.isArray(res.contracts) ? (res.contracts as Raw[]) : [];
  const now = Date.now();
  const rows = list.map((c) => {
    const terms = (Array.isArray(c.terms) ? c.terms : []) as Raw[];
    const ends = terms.map((t) => day(t.endDate)).filter(Boolean).sort();
    const end = ends[ends.length - 1] ?? day(c.endDate ?? c.expirationDate);
    return compact({
      contract: clean(c.contractNumber, 60),
      sku: clean(c.sku ?? c.contractSKU, 80),
      status: clean(c.status, 40),
      description: clean(c.description ?? c.productDescription, 200),
      end,
      daysLeft: end ? daysLeft(end, now) : undefined,
      units: tidy(c.serialNumbers ?? c.units ?? c.assets, 2, 20),
      terms: terms.length ? terms.slice(0, 20).map((t) => compact({ supportType: clean(t.supportType, 80), start: day(t.startDate), end: day(t.endDate) })) : undefined,
    });
  });
  rows.sort((a, b) => (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity));
  const { items, ...paging } = pageOf(rows, int(args.limit)!, int(args.offset)!);
  return { ...paging, contracts: items };
}

async function listFolders(args: Raw, api: Api) {
  const res = await api.asset('/folders/list', {});
  const rows = (Array.isArray(res.folders) ? (res.folders as Raw[]) : [])
    .map((f) =>
      compact({
        folderId: num(f.folderId ?? f.id),
        name: clean(f.folderName ?? f.name, 200),
        path: clean(f.folderPath ?? f.path, 300),
        parentId: num(f.parentFolderId ?? f.parentId),
        assets: num(f.assetCount ?? f.count),
      })
    )
    .filter((f) => has(f.path ?? f.name, str(args.name)));
  const { items, ...paging } = pageOf(rows, int(args.limit)!, int(args.offset)!);
  return { ...paging, folders: items };
}

// --- Search ------------------------------------------------------------------------------------------

async function search(args: Raw, api: Api) {
  const q = str(args.query)!;
  if (q.length < 2) throw new InputError('query must be at least 2 characters');
  let devicesComplete = true;
  const devices = devicesWithAccounts(api).then(
    ({ rows, complete }) => {
      devicesComplete = complete;
      return rows.filter((r) => has(r.name, q) || has(r.serial, q) || has(r.account, q)).slice(0, 25);
    },
    (err) => ({ error: partError(err) })
  );
  const looksLikeSerial = /^[A-Za-z0-9-]{4,40}$/.test(q) && /\d/.test(q);
  const assets =
    args.include_assets && looksLikeSerial
      ? api.asset('/products/list', { serialNumber: q.toUpperCase(), pageNumber: 1 }).then(
          (res) => assetsOf(res).slice(0, 25).map((a) => {
            const { entitlements, ...rest } = assetRow(a);
            return rest;
          }),
          (err) => ({ error: partError(err) })
        )
      : Promise.resolve(undefined);
  const [d, a] = await Promise.all([devices, assets]);
  return compact({
    query: q,
    fortigateCloudDevices: d,
    ...completeness(devicesComplete),
    assetManagement: a,
    note: looksLikeSerial || !args.include_assets ? undefined : 'Asset Management is searched only by serial number (prefix); this query is not one.',
  });
}

// --- Specs -------------------------------------------------------------------------------------------

export const READ_SPECS: ToolSpec[] = [
  {
    name: 'forticloud_status',
    description:
      'Checks the FortiCloud connection: gets a token for FortiGate Cloud and Asset Management, counts the FortiGates in FortiGate Cloud (online/offline) and the Asset Management folders. Each portal is reported separately, so one failing does not hide the other. Start here when other tools fail.',
    params: {},
    untrusted: false,
    run: (_a, api) => status(api),
  },
  {
    name: 'forticloud_list_accounts',
    description:
      'FortiGate Cloud sub-accounts (for an MSSP account, usually one per client), with how many FortiGates each has and how many are offline.',
    params: { name: { type: 'string', description: 'Only accounts whose name contains this text.', maxLength: 100 }, limit: limit(100, 500), offset },
    run: listAccounts,
  },
  {
    name: 'forticloud_list_devices',
    description:
      "FortiGates in FortiGate Cloud with model, serial, firmware, sub-account (client) and whether the management tunnel to FortiGate Cloud is up (connection: online/offline), offline first. Filter by account, connection, model, firmware or name/serial. Each page has total and nextOffset.",
    params: {
      account,
      connection: { type: 'string', description: 'Only devices whose FortiGate Cloud connection is online or offline.', enum: ['online', 'offline', 'unknown'] },
      name: { type: 'string', description: 'Only devices whose name or serial contains this text.', maxLength: 100 },
      model: { type: 'string', description: 'Only this model (contains), e.g. 60F.', maxLength: 60 },
      firmware: { type: 'string', description: 'Only this firmware (contains), e.g. 7.2.', maxLength: 40 },
      limit: limit(50),
      offset,
    },
    run: listDevices,
  },
  {
    name: 'forticloud_get_device',
    description:
      "One FortiGate by serial: FortiGate Cloud details (connection, firmware, account, any other fields the API returns), its automatic config backup settings, and (include_asset) its Asset Management record with entitlements and expiry.",
    params: {
      serial,
      include_asset: { type: 'boolean', description: 'Also read the Asset Management record (entitlements, support end).', default: true },
    },
    run: getDevice,
  },
  {
    name: 'forticloud_firmware_summary',
    description:
      'FortiGate firmware across FortiGate Cloud: devices per firmware version (oldest first) with models and offline counts, and per major version (7.0, 7.2, 7.4...). Optionally for one account or model, and with the devices on each version.',
    params: {
      account,
      model: { type: 'string', description: 'Only this model (contains).', maxLength: 60 },
      list_devices: { type: 'boolean', description: 'List the devices (serial, name, account) on each version.', default: false },
    },
    run: firmwareSummary,
  },
  {
    name: 'forticloud_config_backup_status',
    description:
      "FortiGate Cloud's automatic config backup settings for one FortiGate (serial) or a page of FortiGates (optionally one account). Reads one setting per device, so pages are small; stops after three errors.",
    params: {
      serial: { type: 'string', description: 'One FortiGate. Leave out for a page of all devices.', maxLength: 40 },
      account,
      limit: limit(20, 50),
      offset,
    },
    run: configBackupStatus,
  },
  {
    name: 'forticloud_search',
    description:
      'Finds FortiGates by name, serial or account name in FortiGate Cloud and, when the text looks like a serial (or its start), registered products in Asset Management.',
    params: {
      query: { type: 'string', description: 'Name, serial or account text (2+ characters).', required: true, maxLength: 100 },
      include_assets: { type: 'boolean', description: 'Also search Asset Management by serial.', default: true },
    },
    run: search,
  },
  {
    name: 'forticloud_list_assets',
    description:
      'Registered products in Asset Management whose serial starts with serial_prefix (FG = FortiGates, FS = FortiSwitches, FP = FortiAPs, F = everything), 25 per page: model, description, folder, registration, support end and the next entitlement to expire. Decommissioned products are left out unless asked.',
    params: {
      serial_prefix: { type: 'string', description: 'Start of the serial numbers (FortiCloud needs one).', maxLength: 40, default: 'FG' },
      page: { type: 'int', description: 'First Asset Management page (1-based, 25 products each); use nextPage.', min: 1, max: 1000, default: 1 },
      pages: { type: 'int', description: 'Pages to read in this call (1-4).', min: 1, max: 4, default: 2 },
      model: { type: 'string', description: 'Only this model (contains).', maxLength: 80 },
      folder: { type: 'string', description: 'Only products in a folder whose path contains this text.', maxLength: 100 },
      include_decommissioned: { type: 'boolean', description: 'Include decommissioned products.', default: false },
    },
    run: listAssets,
  },
  {
    name: 'forticloud_get_asset',
    description:
      'One registered product from Asset Management by serial: model, folder, every entitlement (support, FortiGuard services) with start, end and days left, contracts and their terms, licence numbers, warranty, end of order and end of support dates.',
    params: { serial },
    run: getAsset,
  },
  {
    name: 'forticloud_list_expiring',
    description:
      'Support, FortiGuard and other entitlements that expire within `days` (default 60), soonest first, from Asset Management. Only the latest entitlement of each type per product counts, so a renewed service is not listed. include_expired_days also shows ones that ended in the last N days. Filter by serial_prefix (FG for FortiGates), entitlement type or folder.',
    params: {
      days: { type: 'int', description: 'Days ahead (1-730).', min: 1, max: 730, default: 60 },
      include_expired_days: { type: 'int', description: 'Also include entitlements that ended in the last N days (0-730).', min: 0, max: 730, default: 0 },
      serial_prefix: { type: 'string', description: 'Only products whose serial starts with this (FG = FortiGates).', maxLength: 40 },
      type: { type: 'string', description: 'Only entitlement types containing this text, e.g. Support or FortiGuard.', maxLength: 80 },
      folder: { type: 'string', description: 'Only products in a folder whose path contains this text.', maxLength: 100 },
      include_decommissioned: { type: 'boolean', description: 'Include decommissioned products.', default: false },
      limit: limit(100),
      offset,
    },
    run: listExpiring,
  },
  {
    name: 'forticloud_list_contracts',
    description: 'Contracts in Asset Management (support and service contracts) with SKU, status, terms and end date, soonest end first.',
    params: {
      status: { type: 'string', description: 'Registered or Pending.', enum: ['Registered', 'Pending'] },
      contract_number: { type: 'string', description: 'One contract number.', maxLength: 40 },
      limit: limit(100),
      offset,
    },
    run: listContracts,
  },
  {
    name: 'forticloud_list_folders',
    description: 'Asset Management folders (often one per client or site), with their paths and IDs.',
    params: { name: { type: 'string', description: 'Only folders whose path contains this text.', maxLength: 100 }, limit: limit(200, 500), offset },
    run: listFolders,
  },
];

