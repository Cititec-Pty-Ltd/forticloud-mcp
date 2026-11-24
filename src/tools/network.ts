import type { Api } from '../client.js';
import type { FortiosEndpointName, FortiosResult } from '../fortios.js';
import { ForticloudApiError, ForticloudRateLimitError } from '../types.js';
import { checkSerial, timeIn } from './format.js';
import type { DeviceRow } from './format.js';
import { cidr, isPrivate, parseFortiosNet, parseQuery, relate, subnetText } from './ip.js';
import type { Net, Relation } from './ip.js';
import { completeness, devicesWithAccounts, matchAccount, partError, rethrowRateLimit } from './read.js';
import { InputError, clean, compact, num } from './shared.js';
import type { ToolSpec } from './spec.js';

type Raw = Record<string, unknown>;

const str = (v: unknown) => v as string | undefined;
const int = (v: unknown) => v as number | undefined;

/** Text from a FortiOS field, cleaned and cut. */
const text = (v: unknown, max = 120) => clean(v, max);
/** A FortiOS address that is not "0.0.0.0" (FortiOS writes that for "none"). */
const addr = (v: unknown) => {
  const s = clean(v, 60);
  return s && s !== '0.0.0.0' && s !== '0.0.0.0 0.0.0.0' ? s : undefined;
};

/** The device's name, account and connection from the (cached) FortiGate Cloud list; just the serial when it cannot be read. */
async function deviceInfo(api: Api, sn: string): Promise<{ row: Partial<DeviceRow> & { serial: string }; note?: string }> {
  try {
    const { rows } = await devicesWithAccounts(api);
    const row = rows.find((r) => r.serial.toUpperCase() === sn);
    return row ? { row } : { row: { serial: sn }, note: 'This serial is not in the FortiGate Cloud device list.' };
  } catch (err) {
    rethrowRateLimit(err);
    return { row: { serial: sn }, note: `The device list could not be read: ${partError(err)}` };
  }
}

// --- forticloud_get_network ----------------------------------------------------------------------

export const SECTIONS = ['interfaces', 'dhcp', 'routes', 'vips', 'vpn', 'addresses'] as const;
type Section = (typeof SECTIONS)[number];
const DEFAULT_SECTIONS: Section[] = ['interfaces', 'dhcp', 'routes', 'vips', 'vpn'];

interface Ctx {
  api: Api;
  sn: string;
  vdom?: string;
  maxRows: number;
  allInterfaces: boolean;
  /** FortiOS version and VDOM, from the first answer that has them. */
  meta: { version?: string; build?: number; vdom?: string };
}

async function read(ctx: Ctx, endpoint: FortiosEndpointName): Promise<FortiosResult> {
  const r = await ctx.api.fortios(ctx.sn, endpoint, ctx.vdom !== undefined ? { vdom: ctx.vdom } : {});
  ctx.meta.version ??= r.version;
  ctx.meta.build ??= r.build;
  ctx.meta.vdom ??= r.vdom;
  return r;
}

/** Two reads where either alone is useful: both results, or the first error when both fail. */
async function both(ctx: Ctx, a: FortiosEndpointName, b: FortiosEndpointName) {
  const [ra, rb] = await Promise.allSettled([read(ctx, a), read(ctx, b)]);
  for (const r of [ra, rb]) if (r.status === 'rejected') rethrowRateLimit(r.reason);
  if (ra.status === 'rejected' && rb.status === 'rejected') throw ra.reason;
  return {
    a: ra.status === 'fulfilled' ? ra.value : undefined,
    b: rb.status === 'fulfilled' ? rb.value : undefined,
    aError: ra.status === 'rejected' ? partError(ra.reason) : undefined,
    bError: rb.status === 'rejected' ? partError(rb.reason) : undefined,
  };
}

/** Public: a usable address that is not private (see isPrivate). */
const isPublicNet = (n: Net | undefined) => (n ? !isPrivate(n.ip) : false);

async function interfaces(ctx: Ctx) {
  const r = await both(ctx, 'interfaceConfig', 'interfaceLive');
  const live = new Map<string, Raw>();
  for (const row of r.b?.rows ?? []) if (typeof row.name === 'string') live.set(row.name, row);
  const configured = r.a?.rows ?? [];
  const names = new Set<string>();
  const rows: (Raw & { _sort: number })[] = [];
  const build = (c: Raw | undefined, l: Raw | undefined) => {
    const name = String(c?.name ?? l?.name);
    names.add(name);
    const conf = parseFortiosNet(c?.ip);
    const now = parseFortiosNet(l?.ip, l?.mask);
    const secondary = (Array.isArray(c?.secondaryip) ? (c.secondaryip as Raw[]) : [])
      .map((s) => parseFortiosNet(s.ip))
      .filter((n): n is Net => n !== undefined);
    const role = text(c?.role, 20);
    const wan = role === 'wan';
    const isPublic = isPublicNet(conf) || isPublicNet(now) || secondary.some(isPublicNet);
    const link = typeof l?.link === 'boolean' ? (l.link ? 'up' : 'down') : undefined;
    const row = compact({
      name: text(name, 60),
      alias: text(c?.alias ?? l?.alias, 60),
      type: text(c?.type, 30),
      vlanId: num(c?.vlanid) || undefined,
      parent: text(c?.interface, 60),
      role,
      mode: text(c?.mode, 20),
      status: text(c?.status, 10),
      configured: conf ? cidr(conf) : undefined,
      live: now ? cidr(now) : undefined,
      secondary: secondary.length ? secondary.map(cidr) : undefined,
      remoteIp: parseFortiosNet(c?.['remote-ip']) ? cidr(parseFortiosNet(c?.['remote-ip'])!) : undefined,
      link,
      speed: num(l?.speed) ?? text(c?.speed, 20),
      duplex: num(l?.duplex),
      mac: text(l?.mac ?? c?.macaddr, 20),
      members: Array.isArray(c?.member) ? (c.member as Raw[]).map((m) => text(m['interface-name'], 60)).filter(Boolean) : undefined,
      allowaccess: text(c?.allowaccess, 120),
      description: text(c?.description, 200),
      wan: wan || undefined,
      publicIp: isPublic || undefined,
    });
    if (Array.isArray(row.members) && row.members.length === 0) delete row.members;
    const hasAddress = Boolean(conf || now || secondary.length);
    rows.push({ ...row, _sort: wan || isPublic ? 0 : hasAddress ? 1 : 2 });
  };
  for (const c of configured) build(c, typeof c.name === 'string' ? live.get(c.name) : undefined);
  // Live-only interfaces (the configured list could not be read, or it has no entry).
  for (const [name, l] of live) if (!names.has(name)) build(undefined, l);
  rows.sort((x, y) => x._sort - y._sort || String(x.name).localeCompare(String(y.name)));
  const shown = ctx.allInterfaces ? rows : rows.filter((x) => x._sort < 2);
  return compact({
    source: compact({
      configured: r.a ? 'cmdb system/interface' : undefined,
      live: r.b ? 'monitor system/interface' : undefined,
    }),
    configuredError: r.aError,
    liveError: r.bError,
    total: rows.length,
    hiddenWithoutAddress: rows.length - shown.length || undefined,
    note: rows.length > shown.length ? 'Interfaces with no address are left out; set all_interfaces to see them.' : undefined,
    interfaces: shown.slice(0, 500).map(({ _sort, ...rest }) => rest),
  });
}

async function dhcp(ctx: Ctx) {
  const [servers, leases] = await Promise.allSettled([read(ctx, 'dhcpServers'), read(ctx, 'dhcpLeases')]);
  if (servers.status === 'rejected') throw servers.reason;
  if (leases.status === 'rejected') rethrowRateLimit(leases.reason);
  const counts = new Map<string, number>();
  if (leases.status === 'fulfilled') {
    for (const l of leases.value.rows) {
      const i = typeof l.interface === 'string' ? l.interface : '?';
      counts.set(i, (counts.get(i) ?? 0) + 1);
    }
  }
  const rows = servers.value.rows.map((s) => {
    const iface = text(s.interface, 60);
    const dnsMode = text(s['dns-service'], 20);
    const dns = ['dns-server1', 'dns-server2', 'dns-server3', 'dns-server4'].map((k) => addr(s[k])).filter(Boolean);
    const ranges = (Array.isArray(s['ip-range']) ? (s['ip-range'] as Raw[]) : [])
      .map((r) => (addr(r['start-ip']) ? `${addr(r['start-ip'])} - ${addr(r['end-ip']) ?? '?'}` : undefined))
      .filter(Boolean);
    const lease = num(s['lease-time']);
    return compact({
      id: num(s.id),
      interface: iface,
      status: text(s.status, 10),
      ranges: ranges.length ? ranges : undefined,
      netmask: addr(s.netmask),
      gateway: addr(s['default-gateway']),
      dns: compact({ mode: dnsMode, servers: dns.length ? dns : undefined }),
      domain: text(s.domain, 100),
      leaseTimeSeconds: lease,
      leaseTime: lease !== undefined ? (lease === 0 ? 'unlimited' : lease % 86_400 === 0 ? `${lease / 86_400} d` : lease % 3600 === 0 ? `${lease / 3600} h` : `${lease} s`) : undefined,
      activeLeases: leases.status === 'fulfilled' && iface !== undefined ? (counts.get(iface) ?? 0) : undefined,
    });
  });
  return compact({
    source: compact({ configured: 'cmdb system.dhcp/server', leases: leases.status === 'fulfilled' ? 'monitor system/dhcp (count only)' : undefined }),
    leasesError: leases.status === 'rejected' ? partError(leases.reason) : undefined,
    servers: rows.slice(0, ctx.maxRows),
    total: rows.length,
  });
}

const isDefault = (dst: string | undefined) => dst === '0.0.0.0/0';

async function routes(ctx: Ctx) {
  let res: FortiosResult;
  let source: string;
  let liveError: string | undefined;
  try {
    res = await read(ctx, 'routesLive');
    source = 'live (monitor router/ipv4)';
  } catch (err) {
    rethrowRateLimit(err);
    liveError = partError(err);
    res = await read(ctx, 'routesStatic');
    source = 'configured static routes (cmdb router/static); the live table could not be read';
  }
  const live = source.startsWith('live');
  const rows = res.rows.map((r) =>
    live
      ? compact({
          destination: subnetText(r.ip_mask),
          gateway: addr(r.gateway),
          interface: text(r.interface, 60),
          type: text(r.type, 20),
          distance: num(r.distance),
          metric: num(r.metric),
          priority: num(r.priority),
          tunnel: r.is_tunnel_route === true || undefined,
        })
      : compact({
          destination: subnetText(r.dst) ?? '0.0.0.0/0',
          gateway: addr(r.gateway),
          interface: text(r.device, 60),
          type: 'static',
          status: text(r.status, 10),
          distance: num(r.distance),
          priority: num(r.priority),
          blackhole: r.blackhole === 'enable' || undefined,
          comment: text(r.comment, 200),
        })
  );
  const byType: Record<string, number> = {};
  for (const r of rows) byType[String(r.type ?? '?')] = (byType[String(r.type ?? '?')] ?? 0) + 1;
  const defaults = rows.filter((r) => isDefault(r.destination as string | undefined));
  const ordered = [...defaults, ...rows.filter((r) => !isDefault(r.destination as string | undefined))];
  return compact({
    source,
    liveError,
    total: rows.length,
    truncated: res.truncated,
    byType,
    defaultRoutes: defaults.length ? defaults : undefined,
    note: defaults.length ? undefined : 'No default route (0.0.0.0/0) in this table.',
    routes: ordered.slice(0, ctx.maxRows),
    nextRows: rows.length > ctx.maxRows ? `${rows.length - ctx.maxRows} more; raise max_rows to see them` : undefined,
  });
}

async function vips(ctx: Ctx) {
  const res = await read(ctx, 'vips');
  const rows = res.rows.map((v) => {
    const pf = v.portforward === 'enable';
    const mapped = (Array.isArray(v.mappedip) ? (v.mappedip as Raw[]) : []).map((m) => text(m.range, 60)).filter(Boolean);
    return compact({
      name: text(v.name, 80),
      type: text(v.type, 30),
      status: text(v.status, 10),
      externalIp: text(v.extip, 60),
      externalInterface: text(v.extintf, 60),
      externalPort: pf ? text(v.extport, 30) : undefined,
      mappedIp: mapped.length ? mapped.join(', ') : undefined,
      mappedPort: pf ? text(v.mappedport, 30) : undefined,
      protocol: pf ? text(v.protocol, 10) : undefined,
      portForward: pf || undefined,
      comment: text(v.comment, 200),
    });
  });
  return compact({ source: 'configured (cmdb firewall/vip)', total: rows.length, vips: rows.slice(0, ctx.maxRows) });
}

async function vpn(ctx: Ctx) {
  const [liveR, p1R, p2R] = await Promise.allSettled([read(ctx, 'ipsecLive'), read(ctx, 'ipsecPhase1'), read(ctx, 'ipsecPhase2')]);
  for (const r of [liveR, p1R, p2R]) if (r.status === 'rejected') rethrowRateLimit(r.reason);
  if (liveR.status === 'rejected' && p1R.status === 'rejected') throw p1R.reason;
  const live = new Map<string, Raw>();
  if (liveR.status === 'fulfilled') for (const t of liveR.value.rows) if (typeof t.name === 'string') live.set(t.name, t);
  const p2ByP1 = new Map<string, Raw[]>();
  if (p2R.status === 'fulfilled') {
    for (const p of p2R.value.rows) {
      const k = String(p.phase1name ?? '');
      p2ByP1.set(k, [...(p2ByP1.get(k) ?? []), p]);
    }
  }
  const side = (p: Raw, pre: 'src' | 'dst') => {
    const type = text(p[`${pre}-addr-type`], 20);
    if (type === 'name') return text(p[`${pre}-name`], 80);
    if (type === 'range') return `${addr(p[`${pre}-start-ip`]) ?? '?'} - ${addr(p[`${pre}-end-ip`]) ?? '?'}`;
    return subnetText(p[`${pre}-subnet`]);
  };
  const subnets = (list: unknown) => (Array.isArray(list) ? (list as Raw[]).map((x) => subnetText(x.subnet)).filter(Boolean) : []);
  const tunnel = (name: string, p1: Raw | undefined, l: Raw | undefined) => {
    const liveP2 = Array.isArray(l?.proxyid) ? (l.proxyid as Raw[]) : [];
    const phase2 = liveP2.length
      ? liveP2.map((p) => compact({ name: text(p.p2name, 80), status: text(p.status, 10), local: subnets(p.proxysrc), remote: subnets(p.proxydst) }))
      : (p2ByP1.get(name) ?? []).map((p) => compact({ name: text(p.name, 80), local: side(p, 'src'), remote: side(p, 'dst') }));
    const up = liveP2.some((p) => p.status === 'up');
    return compact({
      name: text(name, 80),
      type: text(p1?.type ?? l?.type, 20),
      interface: text(p1?.interface, 60),
      remoteGateway: addr(l?.rgwy) ?? addr(p1?.['remote-gw']) ?? text(p1?.['remotegw-ddns'], 120),
      ikeVersion: text(p1?.['ike-version'], 4),
      status: l ? (up ? 'up' : 'down') : liveR.status === 'fulfilled' ? 'down' : undefined,
      phase2: phase2.length ? phase2.slice(0, 50) : undefined,
      comments: text(p1?.comments ?? l?.comments, 200),
    });
  };
  const rows: Raw[] = [];
  const seen = new Set<string>();
  for (const p1 of p1R.status === 'fulfilled' ? p1R.value.rows : []) {
    const name = String(p1.name ?? '');
    seen.add(name);
    rows.push(tunnel(name, p1, live.get(name)));
  }
  // Live entries with no phase 1 of their own: dial-up instances, or phase 1 unreadable.
  for (const [name, l] of live) if (!seen.has(name)) rows.push(tunnel(name, undefined, l));
  return compact({
    source: compact({
      live: liveR.status === 'fulfilled' ? 'monitor vpn/ipsec' : undefined,
      configured: p1R.status === 'fulfilled' ? 'cmdb vpn.ipsec/phase1-interface + phase2-interface' : undefined,
    }),
    liveError: liveR.status === 'rejected' ? partError(liveR.reason) : undefined,
    configuredError: p1R.status === 'rejected' ? partError(p1R.reason) : p2R.status === 'rejected' ? partError(p2R.reason) : undefined,
    total: rows.length,
    up: liveR.status === 'fulfilled' ? rows.filter((r) => r.status === 'up').length : undefined,
    tunnels: rows.slice(0, ctx.maxRows),
  });
}

async function addresses(ctx: Ctx) {
  const res = await read(ctx, 'addresses');
  const byType: Record<string, number> = {};
  const rows: Raw[] = [];
  for (const a of res.rows) {
    const type = text(a.type, 20) ?? 'ipmask';
    byType[type] = (byType[type] ?? 0) + 1;
    if (type === 'ipmask') rows.push(compact({ name: text(a.name, 80), subnet: subnetText(a.subnet), interface: text(a['associated-interface'], 60), comment: text(a.comment, 200) }));
    else if (type === 'iprange')
      rows.push(compact({ name: text(a.name, 80), range: `${addr(a['start-ip']) ?? '?'} - ${addr(a['end-ip']) ?? '?'}`, interface: text(a['associated-interface'], 60), comment: text(a.comment, 200) }));
  }
  return compact({
    source: 'configured (cmdb firewall/address)',
    total: res.rows.length,
    byType,
    note: 'Only subnet (ipmask) and range objects are listed; the other types are counted in byType.',
    addresses: rows.slice(0, ctx.maxRows),
    nextRows: rows.length > ctx.maxRows ? `${rows.length - ctx.maxRows} more; raise max_rows to see them` : undefined,
  });
}

const RUN: Record<Section, (ctx: Ctx) => Promise<unknown>> = { interfaces, dhcp, routes, vips, vpn, addresses };

async function getNetwork(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const vdom = str(args.vdom);
  if (vdom !== undefined && !/^[A-Za-z0-9_.-]{1,31}$/.test(vdom)) throw new InputError('vdom must be a VDOM name (letters, digits, _ . -)');
  const wanted = (args.sections as Section[] | undefined) ?? DEFAULT_SECTIONS;
  const sections = SECTIONS.filter((s) => wanted.includes(s));
  const ctx: Ctx = { api, sn, vdom, maxRows: int(args.max_rows)!, allInterfaces: args.all_interfaces === true, meta: {} };
  const device = await deviceInfo(api, sn);
  const out: Record<string, unknown> = {};
  // The first section goes alone: if the device does not answer at all, the
  // rest are not tried (FortiGate Cloud allows few errors a minute).
  let unreachable: string | undefined;
  try {
    out[sections[0]] = await RUN[sections[0]](ctx);
  } catch (err) {
    out[sections[0]] = { error: partError(err) };
    if (!(err instanceof ForticloudApiError && err.httpStatus === 404)) unreachable = sections[0];
  }
  const rest = sections.slice(1);
  const results = await Promise.all(
    rest.map((s) =>
      unreachable
        ? Promise.resolve({ skipped: `not tried: the ${unreachable} read failed, so the device is probably not reachable through FortiGate Cloud` })
        : RUN[s](ctx).catch((err) => ({ error: partError(err) }))
    )
  );
  rest.forEach((s, i) => (out[s] = results[i]));
  return compact({
    device: compact({
      serial: sn,
      name: device.row.name,
      account: device.row.account,
      model: device.row.model,
      firmware: device.row.firmware,
      fortigateCloudConnection: device.row.connection,
    }),
    fortios: compact({ version: ctx.meta.version, build: ctx.meta.build, vdom: ctx.meta.vdom ?? vdom }),
    readAt: timeIn(Date.now()),
    note: device.note,
    warning:
      device.row.connection === 'offline'
        ? 'FortiGate Cloud shows this device offline (management tunnel down); the FortiOS reads go through that tunnel and may fail.'
        : undefined,
    ...out,
  });
}

// --- forticloud_find_ip --------------------------------------------------------------------------

/** Limits for forticloud_find_ip. Exported so tests can shorten them. */
export const FIND_IP_LIMITS = {
  /** Wall-clock budget for one call; on expiry the call returns what it has. */
  budgetMs: 45_000,
  /** Devices read at once (each is two FortiOS reads, under the client's own cap of 6 in flight). */
  concurrency: 4,
  /** Failed devices before the call stops asking (FortiGate Cloud allows about 15 errors a minute). */
  maxErrors: 6,
  /** How long one device's interface list is reused. */
  cacheMs: 10 * 60_000,
};

interface IfaceNet {
  interface: string;
  alias?: string;
  type?: string;
  vlanId?: number;
  parent?: string;
  role?: string;
  net: Net;
  source: 'configured' | 'live' | 'configured secondary' | 'configured and live';
}

const ifaceCache = new Map<string, { at: number; value: Promise<IfaceNet[]> }>();

export function clearNetworkCaches(): void {
  ifaceCache.clear();
}

/** One device's interface addresses (configured, secondary and live), from both interface endpoints. */
async function deviceNets(api: Api, sn: string): Promise<IfaceNet[]> {
  const [cfg, live] = await Promise.allSettled([api.fortios(sn, 'interfaceConfig'), api.fortios(sn, 'interfaceLive')]);
  for (const r of [cfg, live]) if (r.status === 'rejected') rethrowRateLimit(r.reason);
  if (cfg.status === 'rejected' && live.status === 'rejected') throw cfg.reason;
  const meta = new Map<string, Omit<IfaceNet, 'net' | 'source'>>();
  const nets: IfaceNet[] = [];
  const push = (n: Net | undefined, name: string, source: IfaceNet['source']) => {
    if (!n) return;
    const same = nets.find((x) => x.interface === name && x.net.ip === n.ip && x.net.prefix === n.prefix);
    if (same) {
      if (same.source !== source) same.source = 'configured and live';
      return;
    }
    nets.push({ ...(meta.get(name) ?? { interface: name }), net: n, source });
  };
  for (const c of cfg.status === 'fulfilled' ? cfg.value.rows : []) {
    const name = String(c.name ?? '');
    if (!name) continue;
    meta.set(
      name,
      compact({
        interface: name,
        alias: text(c.alias, 60),
        type: text(c.type, 30),
        vlanId: num(c.vlanid) || undefined,
        parent: text(c.interface, 60),
        role: text(c.role, 20),
      }) as Omit<IfaceNet, 'net' | 'source'>
    );
    push(parseFortiosNet(c.ip), name, 'configured');
    for (const s of Array.isArray(c.secondaryip) ? (c.secondaryip as Raw[]) : []) push(parseFortiosNet(s.ip), name, 'configured secondary');
  }
  for (const l of live.status === 'fulfilled' ? live.value.rows : []) {
    const name = String(l.name ?? '');
    if (name) push(parseFortiosNet(l.ip, l.mask), name, 'live');
  }
  return nets;
}

function cachedNets(api: Api, sn: string): { value: Promise<IfaceNet[]>; cached: boolean } {
  const key = `${api.cacheKey}|${sn}`;
  const hit = ifaceCache.get(key);
  if (hit && Date.now() - hit.at < FIND_IP_LIMITS.cacheMs) return { value: hit.value, cached: true };
  const value = deviceNets(api, sn);
  ifaceCache.set(key, { at: Date.now(), value });
  value.catch(() => ifaceCache.delete(key));
  return { value, cached: false };
}

const RELATION_ORDER: Record<Relation, number> = {
  'interface address': 0,
  'inside the interface subnet': 1,
  'same subnet': 1,
  'contains the interface subnet': 2,
};

async function findIp(args: Raw, api: Api) {
  const q = parseQuery(str(args.query)!);
  if (!q) throw new InputError('query must be an IPv4 address (192.0.2.10) or subnet (192.0.2.0/24)');
  if (q.prefix < 8) throw new InputError('query subnets must be /8 or longer');
  const { rows, complete } = await devicesWithAccounts(api);
  const inScope = rows.filter((r) => matchAccount(r, str(args.account)));
  const online = inScope.filter((r) => r.connection === 'online');
  const notQueried = inScope.filter((r) => r.connection !== 'online');

  const deadline = Date.now() + FIND_IP_LIMITS.budgetMs;
  const matches: (Raw & { _order: number; _prefix: number })[] = [];
  const errors: Raw[] = [];
  let searched = 0;
  let fromCache = 0;
  let stopped: 'budget' | 'errors' | undefined;
  let rateLimit: ForticloudRateLimitError | undefined;
  const started = new Set<string>();
  const finished = new Set<string>();

  const queue = [...online];
  const worker = async () => {
    for (;;) {
      if (rateLimit || stopped === 'errors') return;
      if (Date.now() >= deadline) {
        stopped ??= 'budget';
        return;
      }
      const d = queue.shift();
      if (!d) return;
      started.add(d.serial);
      const { value, cached } = cachedNets(api, d.serial);
      try {
        const nets = await value;
        // A device that answered after the budget ran out is not counted (its answer is cached for the next call).
        if (Date.now() > deadline && !cached) {
          stopped ??= 'budget';
          return;
        }
        searched++;
        if (cached) fromCache++;
        finished.add(d.serial);
        for (const n of nets) {
          const rel = relate(q, n.net);
          if (!rel) continue;
          matches.push({
            ...compact({
              account: d.account,
              device: d.name,
              serial: d.serial,
              interface: n.interface,
              alias: n.alias,
              type: n.type,
              vlanId: n.vlanId,
              parent: n.parent,
              role: n.role,
              interfaceAddress: cidr(n.net),
              source: n.source,
              match: rel,
              publicIp: !isPrivate(n.net.ip) || undefined,
            }),
            _order: RELATION_ORDER[rel],
            _prefix: n.net.prefix,
          });
        }
      } catch (err) {
        finished.add(d.serial);
        if (err instanceof ForticloudRateLimitError) {
          rateLimit = err;
          return;
        }
        errors.push(compact({ serial: d.serial, device: d.name, account: d.account, error: partError(err) }));
        if (errors.length >= FIND_IP_LIMITS.maxErrors) stopped = 'errors';
      }
    }
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const budget = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      stopped ??= 'budget';
      resolve();
    }, Math.max(0, deadline - Date.now()));
  });
  await Promise.race([Promise.all(Array.from({ length: FIND_IP_LIMITS.concurrency }, worker)), budget]);
  clearTimeout(timer);
  if (rateLimit) throw rateLimit;

  // Merge rows that are the same address on the same interface (configured and live).
  const merged = new Map<string, (typeof matches)[number]>();
  for (const m of matches) {
    const key = `${m.serial}|${m.interface}|${m.interfaceAddress}`;
    const cur = merged.get(key);
    if (cur) cur.source = cur.source === m.source ? cur.source : 'configured and live';
    else merged.set(key, m);
  }
  const sorted = [...merged.values()].sort(
    (a, b) => a._order - b._order || b._prefix - a._prefix || String(a.account ?? '').localeCompare(String(b.account ?? '')) || String(a.device ?? '').localeCompare(String(b.device ?? ''))
  );
  const limit = int(args.limit)!;
  const skipped = online.filter((d) => !finished.has(d.serial));
  const describe = (d: DeviceRow) => compact({ serial: d.serial, device: d.name, account: d.account });
  const partial = skipped.length > 0 || errors.length > 0;
  return compact({
    query: q.host ? cidr({ ip: q.ip, prefix: 32 }).replace(/\/32$/, '') : cidr(q),
    matches: sorted.length,
    results: sorted.slice(0, limit).map(({ _order, _prefix, ...rest }) => rest),
    devices: compact({
      inScope: inScope.length,
      online: online.length,
      searched,
      fromCache: fromCache || undefined,
      failed: errors.length || undefined,
      skipped: skipped.length || undefined,
      notQueried: notQueried.length || undefined,
    }),
    complete: partial || !complete ? false : undefined,
    warning: !complete ? completeness(false).warning : undefined,
    stoppedBecause:
      stopped === 'budget' && skipped.length
        ? `the ${Math.round(FIND_IP_LIMITS.budgetMs / 1000)} s time budget ran out; call again to continue (devices already read are cached for ${Math.round(FIND_IP_LIMITS.cacheMs / 60_000)} min)`
        : stopped === 'errors'
          ? `${errors.length} devices failed, so no more were asked (FortiGate Cloud allows few errors a minute)`
          : undefined,
    skippedDevices: skipped.length ? skipped.slice(0, 100).map((d) => ({ ...describe(d), reason: started.has(d.serial) ? 'still reading when the budget ran out' : 'not reached' })) : undefined,
    failedDevices: errors.length ? [...errors] : undefined,
    notQueriedDevices: notQueried.length
      ? notQueried.slice(0, 100).map((d) => ({ ...describe(d), reason: d.connection === 'offline' ? 'offline in FortiGate Cloud' : 'connection unknown' }))
      : undefined,
    note: 'Matches IPv4 interface addresses and subnets (configured, secondary and live) on FortiGates that are online in FortiGate Cloud. Routes, VIPs and address objects are not searched.',
  });
}

// --- Specs -------------------------------------------------------------------------------------------

export const NETWORK_SPECS: ToolSpec[] = [
  {
    name: 'forticloud_get_network',
    description:
      "One FortiGate's network, read live from the device through FortiGate Cloud (read-only FortiOS API): interfaces (type, VLAN ID and parent, role, addressing mode, configured and live IP in CIDR, link, speed, MAC, description; WAN and public addresses marked), DHCP servers (ranges, gateway, DNS, lease time, active lease count), the routing table with the default route, VIPs (port forwards), IPsec VPN tunnels (remote gateway, up/down, local and remote subnets) and optionally firewall address objects. Each section says whether it is live or configured. Never returns passwords, keys or certificates.",
    params: {
      serial: { type: 'string', description: 'The FortiGate serial number, e.g. FGT60FTK00000000.', required: true, maxLength: 40 },
      sections: {
        type: 'string_list',
        description: `Sections to read (default ${DEFAULT_SECTIONS.join(', ')}; addresses only when asked).`,
        enum: SECTIONS,
        maxItems: SECTIONS.length,
      },
      all_interfaces: { type: 'boolean', description: 'Also list interfaces with no IP address.', default: false },
      max_rows: { type: 'int', description: 'Most rows per section for routes, VIPs, tunnels, DHCP servers and addresses (1-500).', min: 1, max: 500, default: 50 },
      vdom: { type: 'string', description: 'The VDOM, on a FortiGate with VDOMs (default: the root VDOM).', maxLength: 31 },
    },
    run: getNetwork,
  },
  {
    name: 'forticloud_find_ip',
    description:
      'Which client (FortiGate Cloud sub-account), FortiGate, interface and VLAN an IPv4 address or subnet belongs to. Reads the interface addresses of every online FortiGate (or one account) through FortiGate Cloud, a few at a time within a time budget, and returns the interfaces whose subnet contains the address or overlaps the subnet, exact interface addresses first. Reports offline, failed and skipped devices; a call that runs out of time returns what it found, and devices already read are cached for 10 minutes, so calling again continues.',
    params: {
      query: { type: 'string', description: 'An IPv4 address (198.51.100.7) or subnet (10.20.0.0/16).', required: true, maxLength: 40 },
      account: {
        type: 'string',
        description: 'Only devices of this FortiGate Cloud sub-account (a client): its name (contains, any case) or numeric ID. Much faster.',
        maxLength: 100,
      },
      limit: { type: 'int', description: 'Matches to return (1-200).', min: 1, max: 200, default: 25 },
    },
    run: findIp,
  },
];
