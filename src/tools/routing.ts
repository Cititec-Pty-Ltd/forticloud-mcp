import type { Api } from '../client.js';
import type { FortiosEndpointName, FortiosResult } from '../fortios.js';
import { ForticloudApiError, ForticloudAuthError, ForticloudRateLimitError } from '../types.js';
import { checkSerial, timeIn } from './format.js';
import { parseIpv4, subnetText } from './ip.js';
import { checkVdom, cutInfo, deviceInfo, shownInfo } from './network.js';
import { clean, compact, num } from './shared.js';
import type { ToolSpec } from './spec.js';

/**
 * forticloud_get_routing: how one FortiGate routes to the internet and fails
 * over between WANs. Static routes (every routing field), policy routes,
 * link monitors (configured and live), SD-WAN (configured and live, or
 * `virtual-wan-link` on FortiOS 6.2 and older) and a summary of the failover
 * method, with the default routes cross-checked against the live table.
 *
 * Every read is reported on its own: a read that fails says why (not
 * supported, permission denied, rate limited, failed) and the others still
 * show. After a 429 no further read is started; if nothing could be read the
 * call returns the usual structured rate_limited error.
 */

type Raw = Record<string, unknown>;

const text = (v: unknown, max = 120) => clean(v, max);
/** A FortiOS address that is not "0.0.0.0" (FortiOS writes that for "none"). */
const addr = (v: unknown) => {
  const s = clean(v, 60);
  return s && s !== '0.0.0.0' && s !== '0.0.0.0 0.0.0.0' ? s : undefined;
};
const on = (v: unknown) => v === 'enable';
const list = (v: unknown): Raw[] => (Array.isArray(v) ? (v as Raw[]).filter((x) => !!x && typeof x === 'object') : []);
/** Names from a FortiOS list of {name} (or a plain name, on versions where it is one). */
const names = (v: unknown, key = 'name'): string[] =>
  typeof v === 'string' ? [text(v, 80)].filter((x): x is string => !!x) : list(v).map((x) => text(x[key], 80)).filter((x): x is string => !!x);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** The reads this tool makes, by the label each section reports. */
const READ = {
  static: 'cmdb router/static',
  policy: 'cmdb router/policy',
  lmConfig: 'cmdb system/link-monitor',
  lmLive: 'monitor system/link-monitor',
  sdwan: 'cmdb system/sdwan',
  sdwanLegacy: 'cmdb system/virtual-wan-link',
  hcLive: 'monitor virtual-wan/health-check',
  membersLive: 'monitor virtual-wan/members',
  routesLive: 'monitor router/ipv4',
  ifLive: 'monitor system/interface',
  ipsecLive: 'monitor vpn/ipsec',
} as const;

export type FailReason = 'not_supported' | 'permission_denied' | 'rate_limited' | 'failed' | 'not_tried';

export interface Failure {
  read: string;
  reason: FailReason;
  error: string;
  retryAfterSeconds?: number;
}

type Got = { ok: true; read: string; res: FortiosResult } | { ok: false; read: string; fail: Failure; deviceDown?: boolean };

/** Why a read failed, from its error. */
function failure(read: string, err: unknown): { fail: Failure; deviceDown: boolean } {
  const error = clean((err as Error)?.message, 300) ?? 'failed';
  if (err instanceof ForticloudRateLimitError) {
    return { fail: { read, reason: 'rate_limited', error, retryAfterSeconds: err.retryAfterSeconds }, deviceDown: false };
  }
  // A portal-level refusal (the token, or FortiGate Cloud itself) stops every read; a FortiOS one is this endpoint only.
  if (err instanceof ForticloudAuthError) return { fail: { read, reason: 'permission_denied', error }, deviceDown: true };
  const status = err instanceof ForticloudApiError ? err.httpStatus : undefined;
  if (status === 401 || status === 403) return { fail: { read, reason: 'permission_denied', error }, deviceDown: false };
  if (status === 404 || status === 405 || status === 501) return { fail: { read, reason: 'not_supported', error }, deviceDown: false };
  return { fail: { read, reason: 'failed', error }, deviceDown: true };
}

interface Ctx {
  api: Api;
  sn: string;
  vdom?: string;
  meta: { version?: string; build?: number; vdom?: string };
  /** The first 429: after it no read is started (the fleet policy). */
  rateLimit?: ForticloudRateLimitError;
  answered: number;
}

async function get(ctx: Ctx, endpoint: FortiosEndpointName, read: string): Promise<Got> {
  if (ctx.rateLimit) {
    const s = ctx.rateLimit.retryAfterSeconds;
    return { ok: false, read, fail: { read, reason: 'rate_limited', error: `not asked: FortiCloud rate-limited an earlier read; try again in ${s} s`, retryAfterSeconds: s } };
  }
  try {
    const res = await ctx.api.fortios(ctx.sn, endpoint, {
      ...(ctx.vdom !== undefined ? { vdom: ctx.vdom } : {}),
      // A read queued behind the client's slot limit is not sent once another read got a 429.
      cancelled: () =>
        ctx.rateLimit
          ? new ForticloudRateLimitError(`not asked: FortiCloud rate-limited an earlier read; try again in ${ctx.rateLimit.retryAfterSeconds} s`, ctx.rateLimit.retryAfterSeconds)
          : undefined,
      onRateLimited: (err) => {
        ctx.rateLimit ??= err;
      },
    });
    ctx.meta.version ??= res.version;
    ctx.meta.build ??= res.build;
    ctx.meta.vdom ??= res.vdom;
    ctx.answered++;
    return { ok: true, read, res };
  } catch (err) {
    if (err instanceof ForticloudRateLimitError) ctx.rateLimit ??= err;
    return { ok: false, read, ...failure(read, err) };
  }
}

const notTried = (read: string, why: string): Got => ({ ok: false, read, fail: { read, reason: 'not_tried', error: why } });

/** FortiOS before 6.4 keeps SD-WAN in `system virtual-wan-link`. Unknown versions are taken as 6.4 or later. */
export function isLegacySdwan(version: string | undefined): boolean {
  const m = /^v?(\d+)\.(\d+)/.exec(version ?? '');
  return m ? Number(m[1]) * 100 + Number(m[2]) < 604 : false;
}

/** SD-WAN settings: `system sdwan`, or `system virtual-wan-link` on 6.2 and older (tried in the order the version suggests). */
async function readSdwan(ctx: Ctx): Promise<Got & { legacy?: boolean }> {
  const both: [FortiosEndpointName, string, boolean][] = [
    ['sdwanConfig', READ.sdwan, false],
    ['sdwanLegacy', READ.sdwanLegacy, true],
  ];
  if (isLegacySdwan(ctx.meta.version)) both.reverse();
  const first = await get(ctx, both[0][0], both[0][1]);
  if (first.ok || first.fail.reason !== 'not_supported') return { ...first, legacy: both[0][2] };
  const second = await get(ctx, both[1][0], both[1][1]);
  if (second.ok || second.fail.reason !== 'not_supported') return { ...second, legacy: both[1][2] };
  return { ...first, fail: { ...first.fail, read: `${first.read} and ${second.read}`, error: `${first.fail.error}; ${second.fail.error}` } };
}

// --- Sections ----------------------------------------------------------------------------------------

const MORE = 'raise max_rows to see them';

interface StaticRoute extends Raw {
  linkMonitorExempt?: true;
  seq?: number;
  destination: string;
  destinationAddress?: string;
  gateway?: string;
  interface?: string;
  sdwanZones?: string[];
  viaSdwan?: true;
  distance?: number;
  priority?: number;
  weight?: number;
  status?: string;
  blackhole?: true;
}

function staticRoute(r: Raw): StaticRoute {
  const zones = names(r['sdwan-zone']);
  const viaSdwan = zones.length > 0 || on(r.sdwan) || on(r['virtual-wan-link']);
  return compact({
    seq: num(r['seq-num']),
    destination: subnetText(r.dst) ?? '0.0.0.0/0',
    destinationAddress: text(r.dstaddr, 80),
    gateway: addr(r.gateway),
    interface: text(r.device, 60),
    sdwanZones: zones.length ? zones : undefined,
    viaSdwan: viaSdwan || undefined,
    distance: num(r.distance),
    priority: num(r.priority),
    weight: num(r.weight),
    status: text(r.status, 10),
    blackhole: on(r.blackhole) || undefined,
    dynamicGateway: on(r['dynamic-gateway']) || undefined,
    linkMonitorExempt: on(r['link-monitor-exempt']) || undefined,
    vrf: num(r.vrf) || undefined,
    comment: text(r.comment, 200),
  }) as StaticRoute;
}

const isDefaultRoute = (r: StaticRoute) => r.destination === '0.0.0.0/0' && !r.destinationAddress && !r.blackhole;
const enabled = (status: unknown) => status !== 'disable';

function staticSection(got: Got, routes: StaticRoute[] | undefined, maxRows: number) {
  if (!got.ok) return { ...got.fail };
  const rows = routes ?? [];
  return compact({
    source: `configured (${got.read})`,
    ...cutInfo([[got.read, got.res]]),
    total: rows.length,
    defaultRoutes: rows.filter(isDefaultRoute).length,
    ...shownInfo(rows.length, Math.min(rows.length, maxRows), MORE),
    routes: rows.slice(0, maxRows),
  });
}

function policySection(got: Got, maxRows: number) {
  if (!got.ok) return { ...got.fail };
  const subnets = (v: unknown) => list(v).map((x) => subnetText(x.subnet)).filter((x): x is string => !!x && x !== '0.0.0.0/0');
  const rows = got.res.rows.map((p) => {
    const start = num(p['start-port']);
    const end = num(p['end-port']);
    const anyPort = (start === undefined || start <= 1) && (end === undefined || end >= 65535);
    const src = [...subnets(p.src), ...names(p.srcaddr)];
    const dst = [...subnets(p.dst), ...names(p.dstaddr)];
    return compact({
      seq: num(p['seq-num']),
      status: text(p.status, 10),
      action: text(p.action, 10),
      inputDevices: names(p['input-device']).length ? names(p['input-device']) : undefined,
      source: src.length ? src : undefined,
      destination: dst.length ? dst : undefined,
      protocol: num(p.protocol) || undefined,
      ports: anyPort ? undefined : start === end ? String(start) : `${start ?? 0}-${end ?? 65535}`,
      gateway: addr(p.gateway),
      outputDevice: text(p['output-device'], 60),
      comment: text(p.comments, 200),
    });
  });
  return compact({
    source: `configured (${got.read})`,
    ...cutInfo([[got.read, got.res]]),
    total: rows.length,
    ...shownInfo(rows.length, Math.min(rows.length, maxRows), MORE),
    routes: rows.slice(0, maxRows),
  });
}

/** Live probe results (link-monitor or SD-WAN health check) for one interface. */
function probe(l: Raw) {
  return compact({
    interface: text(l.interface, 60),
    state: text(l.status, 20),
    latencyMs: num(l.latency),
    jitterMs: num(l.jitter),
    packetLossPercent: num(l.packet_loss),
    slaTargetsMet: Array.isArray(l.sla_targets_met) ? l.sla_targets_met : undefined,
    stateChanged: timeIn(num(l.state_changed)),
  });
}

function groupByName(rows: Raw[]): Map<string, Raw[]> {
  const out = new Map<string, Raw[]>();
  for (const r of rows) {
    const k = String(r.name ?? '');
    out.set(k, [...(out.get(k) ?? []), r]);
  }
  return out;
}

interface LinkMonitor {
  name?: string;
  interface?: string;
  status?: string;
  updateStaticRoute?: string;
  servers?: string[];
  protocol?: string;
  gatewayIp?: string;
  /** The monitor's `route` list: when set, only routes to these subnets are removed. */
  routes?: string[];
  live?: Raw[];
}

function linkMonitorRow(m: Raw, live: Raw[] | undefined): Raw & LinkMonitor {
  const servers = names(m.server, 'address');
  const routes = list(m.route).map((r) => subnetText(r.subnet)).filter(Boolean);
  return compact({
    name: text(m.name, 80),
    status: text(m.status, 10),
    interface: text(m.srcintf, 60),
    servers: servers.length ? servers : undefined,
    protocol: text(m.protocol, 60),
    port: num(m.port) || undefined,
    gatewayIp: addr(m['gateway-ip']),
    addrMode: text(m['addr-mode'], 10),
    interval: num(m.interval),
    probeTimeout: num(m['probe-timeout']),
    failtime: num(m.failtime),
    recoverytime: num(m.recoverytime),
    // FortiOS's default is enable, so a missing value counts as enable in the summary.
    updateStaticRoute: text(m['update-static-route'], 10),
    updateCascadeInterface: text(m['update-cascade-interface'], 10),
    updatePolicyRoute: text(m['update-policy-route'], 10),
    routes: routes.length ? routes : undefined,
    live: live ? live.map(probe) : undefined,
  }) as Raw & LinkMonitor;
}

function linkMonitorSection(cfg: Got, live: Got, monitors: (Raw & LinkMonitor)[]) {
  if (!cfg.ok && !live.ok) return { ...cfg.fail, configuredError: cfg.fail, liveError: live.fail };
  return compact({
    source: compact({ configured: cfg.ok ? cfg.read : undefined, live: live.ok ? live.read : undefined }),
    configuredError: cfg.ok ? undefined : cfg.fail,
    liveError: live.ok ? undefined : live.fail,
    ...cutInfo([
      [cfg.read, cfg.ok ? cfg.res : undefined],
      [live.read, live.ok ? live.res : undefined],
    ]),
    total: monitors.length,
    note: monitors.length
      ? 'interval, probeTimeout, failtime and recoverytime are as FortiOS stores them (interval and probe timeout in ms on 7.x, s on older versions); latency and jitter in ms, packet loss in %.'
      : undefined,
    monitors,
  });
}

interface Sdwan {
  enabled?: boolean;
  members: { seq?: number; interface?: string; zone?: string; status?: string; gateway?: string; priority?: number; weight?: number }[];
  healthChecks: { name?: string; server?: string; protocol?: string; members?: string[]; updateStaticRoute?: string }[];
}

function sdwanSection(cfgGot: Got & { legacy?: boolean }, hcGot: Got, memGot: Got, maxRows: number): { section: Raw; sdwan?: Sdwan } {
  const cfg = cfgGot.ok ? (cfgGot.res.rows[0] ?? {}) : undefined;
  const hcLive = groupByName(hcGot.ok ? hcGot.res.rows : []);
  const memLive = new Map<string, Raw>();
  for (const m of memGot.ok ? memGot.res.rows : []) {
    const k = text(m.interface, 60) ?? text(m.name, 60);
    if (k) memLive.set(k, m);
  }
  const seqToIface = new Map<number, string>();
  const members = list(cfg?.members).map((m) => {
    const iface = text(m.interface, 60);
    const seq = num(m['seq-num']);
    if (seq !== undefined && iface) seqToIface.set(seq, iface);
    const l = iface ? memLive.get(iface) : undefined;
    return compact({
      seq,
      interface: iface,
      zone: text(m.zone, 60),
      gateway: addr(m.gateway),
      priority: num(m.priority),
      cost: num(m.cost),
      weight: num(m.weight),
      status: text(m.status, 10),
      comment: text(m.comment, 200),
      live: l
        ? compact({ link: text(l.link, 20), state: text(l.status, 20), sessions: num(l.session), txBandwidth: num(l.tx_bandwidth), rxBandwidth: num(l.rx_bandwidth), stateChanged: timeIn(num(l.state_changed)) })
        : undefined,
    });
  });
  const memberNames = (v: unknown) => {
    const seqs = list(v).map((x) => num(x['seq-num'])).filter((x): x is number => x !== undefined);
    if (seqs.includes(0)) return ['all members'];
    return seqs.map((s) => seqToIface.get(s) ?? `member ${s}`);
  };
  const configured = list(cfg?.['health-check']).map((h) => {
    const name = text(h.name, 80);
    const hcMembers = memberNames(h.members);
    const sla = list(h.sla).map((s) =>
      compact({ id: num(s.id), latencyThresholdMs: num(s['latency-threshold']), jitterThresholdMs: num(s['jitter-threshold']), packetLossThresholdPercent: num(s['packetloss-threshold']) })
    );
    return compact({
      name,
      server: text(h.server, 200),
      protocol: text(h.protocol, 30),
      port: num(h.port) || undefined,
      detectMode: text(h['detect-mode'], 20),
      interval: num(h.interval),
      failtime: num(h.failtime),
      recoverytime: num(h.recoverytime),
      members: hcMembers.length ? hcMembers : undefined,
      sla: sla.length ? sla : undefined,
      updateStaticRoute: text(h['update-static-route'], 10),
      updateCascadeInterface: text(h['update-cascade-interface'], 10),
      live: name && hcLive.has(name) ? hcLive.get(name)!.map(probe) : undefined,
    });
  });
  // Live health checks with no configured entry (the settings could not be read).
  const seen = new Set(configured.map((h) => h.name));
  const liveOnly = [...hcLive.entries()].filter(([n]) => n && !seen.has(n)).map(([name, rows]) => ({ name, live: rows.map(probe) }));
  const healthChecks = [...configured, ...liveOnly];
  const rules = list(cfg?.service).map((s) => {
    const prio = memberNames(s['priority-members']).filter((x) => x !== 'all members');
    const zones = names(s['priority-zone']);
    const hcs = names(s['health-check']);
    const sla = list(s.sla).map((x) => compact({ healthCheck: text(x['health-check'], 80), id: num(x.id) }));
    return compact({
      id: num(s.id),
      name: text(s.name, 80),
      status: text(s.status, 10),
      mode: text(s.mode, 20),
      inputDevices: names(s['input-device']).length ? names(s['input-device']) : undefined,
      source: names(s.src).length ? names(s.src) : undefined,
      destination: names(s.dst).length ? names(s.dst) : undefined,
      priorityMembers: prio.length ? prio : undefined,
      priorityZones: zones.length ? zones : undefined,
      healthChecks: hcs.length ? hcs : undefined,
      sla: sla.length ? sla : undefined,
    });
  });
  const zones = names(cfg?.zone);
  const section = compact({
    source: compact({
      configured: cfgGot.ok ? (cfgGot.legacy ? `${cfgGot.read} (FortiOS 6.2 and older)` : cfgGot.read) : undefined,
      healthChecks: hcGot.ok ? hcGot.read : undefined,
      members: memGot.ok ? memGot.read : undefined,
    }),
    configuredError: cfgGot.ok ? undefined : cfgGot.fail,
    healthCheckLiveError: hcGot.ok ? undefined : hcGot.fail,
    membersLiveError: memGot.ok ? undefined : memGot.fail,
    ...cutInfo([
      [cfgGot.read, cfgGot.ok ? cfgGot.res : undefined],
      [hcGot.read, hcGot.ok ? hcGot.res : undefined],
      [memGot.read, memGot.ok ? memGot.res : undefined],
    ]),
    status: cfg ? (text(cfg.status, 10) ?? 'disable') : undefined,
    loadBalanceMode: text(cfg?.['load-balance-mode'], 30),
    zones: zones.length ? zones : undefined,
    members: members.length ? members : undefined,
    healthChecks: healthChecks.length ? healthChecks : undefined,
    rulesTotal: rules.length || undefined,
    ...shownInfo(rules.length, Math.min(rules.length, maxRows), MORE),
    rules: rules.length ? rules.slice(0, maxRows) : undefined,
  });
  if (!cfgGot.ok && !hcGot.ok && !memGot.ok) return { section: { ...cfgGot.fail, ...section } };
  return {
    section,
    sdwan: cfg ? { enabled: on(cfg.status), members: members as Sdwan['members'], healthChecks: configured as Sdwan['healthChecks'] } : undefined,
  };
}

// --- Route candidates ----------------------------------------------------------------------------------

/**
 * One path to a destination, like a line of `get router info routing-table
 * database`. FortiOS's REST API has no documented read of that database
 * (monitor router/ipv4 lists only the installed routes), so the candidates are
 * derived: every configured static route (SD-WAN routes expanded per member),
 * merged with every route in the live table, and each given a state.
 */
export interface Candidate {
  destination: string;
  gateway?: string;
  interface?: string;
  distance?: number;
  priority?: number;
  weight?: number;
  source: 'static' | 'connected' | 'sdwan' | 'other';
  /** From the configuration (false: only in the live table, e.g. learned by DHCP or PPPoE). */
  configured: boolean;
  seq?: number;
  status?: string;
  blackhole?: true;
  /** link-monitor-exempt: no link-monitor removes this route. */
  linkMonitorExempt?: true;
  sdwanZone?: string;
  liveType?: string;
  monitoredBy?: string[];
  inRoutingTable?: boolean;
  state?: 'active' | 'standby' | 'inactive';
  reason?: string;
}

type CandidateState = Pick<Candidate, 'state' | 'reason'>;

interface LiveRoute {
  destination?: string;
  gateway?: string;
  interface?: string;
  distance?: number;
  priority?: number;
  type?: string;
}

const isNull = (iface: string | undefined) => !!iface && /^(null|blackhole)$/i.test(iface);
const rank = (c: { distance?: number; priority?: number }) => [c.distance ?? 0, c.priority ?? 0] as const;
const better = (a: { distance?: number; priority?: number }, b: { distance?: number; priority?: number }) => {
  const [ad, ap] = rank(a);
  const [bd, bp] = rank(b);
  return ad < bd || (ad === bd && ap < bp);
};
const sameRank = (a: { distance?: number; priority?: number }, b: { distance?: number; priority?: number }) => !better(a, b) && !better(b, a);

/** Sort key: IPv4 destinations by address then prefix length; named destinations after them. */
function destKey(d: string): [number, number, string] {
  const [ip, len] = d.split('/');
  const n = parseIpv4(ip);
  return n === undefined ? [2 ** 32, 0, d] : [n, Number(len ?? 32), d];
}
function byDestination(a: Candidate, b: Candidate) {
  const [an, al, as] = destKey(a.destination);
  const [bn, bl, bs] = destKey(b.destination);
  return an - bn || al - bl || as.localeCompare(bs) || rank(a)[0] - rank(b)[0] || rank(a)[1] - rank(b)[1];
}

export interface Signals {
  /** Monitors that update static routes, with their live state per interface. */
  monitors: (Raw & LinkMonitor)[];
  /** Interface name -> link up, from monitor system/interface. */
  links?: Map<string, boolean>;
  /** Tunnel name -> any phase 2 up, from monitor vpn/ipsec. */
  tunnels?: Map<string, boolean>;
  /** SD-WAN member interface -> the health checks that see it down. */
  sdwanDown: Map<string, string[]>;
}

/** The link monitors that can remove this route: same interface (and gateway, when the monitor names one), the route not exempt, and inside the monitor's own route list when it has one. */
function monitorsFor(c: Candidate, s: Signals) {
  if (c.linkMonitorExempt) return [];
  return s.monitors.filter(
    (m) =>
      enabled(m.status) &&
      m.updateStaticRoute !== 'disable' &&
      m.interface === c.interface &&
      (!m.gatewayIp || !c.gateway || m.gatewayIp === c.gateway) &&
      (!m.routes?.length || m.routes.includes(c.destination))
  );
}

/** Why a route is out of the table, when the data read shows it. */
function blockedBy(c: Candidate, s: Signals): string | undefined {
  if (!enabled(c.status)) return 'disabled in config';
  const dead = monitorsFor(c, s).filter((m) => (m.live as { interface?: string; state?: string }[] | undefined)?.some((l) => l.state === 'dead' && (!l.interface || l.interface === c.interface)));
  if (dead.length) return `link-monitor ${dead.map((m) => m.name ?? '?').join(', ')} reports ${c.interface} dead`;
  if (c.source === 'sdwan' && c.interface && s.sdwanDown.has(c.interface)) return `SD-WAN health check ${s.sdwanDown.get(c.interface)!.join(', ')} reports ${c.interface} down`;
  if (c.interface && s.tunnels?.get(c.interface) === false) return `tunnel ${c.interface} is down`;
  if (c.interface && s.links?.get(c.interface) === false) return `interface ${c.interface} link is down`;
  return undefined;
}

export function buildCandidates(input: { statics?: StaticRoute[]; sdwan?: Sdwan; live?: LiveRoute[]; signals: Signals }): Candidate[] {
  const { statics, sdwan, live, signals } = input;
  const cands: Candidate[] = [];
  for (const s of statics ?? []) {
    const destination = s.destinationAddress ?? s.destination;
    const base = { destination, seq: s.seq, configured: true, status: s.status, distance: s.distance };
    if (s.viaSdwan) {
      const members = (sdwan?.members ?? []).filter((m) => !s.sdwanZones || !m.zone || s.sdwanZones.includes(m.zone));
      if (members.length) {
        for (const m of members) {
          cands.push(
            compact({
              ...base,
              source: 'sdwan',
              gateway: m.gateway ?? s.gateway,
              interface: m.interface,
              priority: m.priority ?? s.priority,
              weight: m.weight ?? s.weight,
              sdwanZone: m.zone ?? s.sdwanZones?.join(', '),
              status: !enabled(s.status) || !enabled(m.status) ? 'disable' : s.status,
            }) as Candidate
          );
        }
      } else {
        cands.push(compact({ ...base, source: 'sdwan', interface: s.sdwanZones?.join(', ') ?? s.interface ?? 'SD-WAN', gateway: s.gateway, priority: s.priority, weight: s.weight }) as Candidate);
      }
    } else {
      cands.push(
        compact({
          ...base,
          source: 'static',
          gateway: s.gateway,
          interface: s.blackhole ? 'blackhole' : s.interface,
          priority: s.priority,
          weight: s.weight,
          blackhole: s.blackhole,
          linkMonitorExempt: s.linkMonitorExempt,
        }) as Candidate
      );
    }
  }
  for (const c of cands) {
    const by = monitorsFor(c, signals).map((m) => m.name ?? '?');
    if (by.length && c.source !== 'sdwan') c.monitoredBy = by;
  }
  if (!live) return cands.sort(byDestination);

  // Install the live routes: each matches one configured candidate, or is a candidate of its own.
  const matched = new Set<Candidate>();
  for (const l of live) {
    if (!l.destination) continue;
    const hit = cands.find(
      (c) =>
        !matched.has(c) &&
        c.destination === l.destination &&
        (c.interface === l.interface || (c.blackhole && isNull(l.interface))) &&
        (!c.gateway || !l.gateway || c.gateway === l.gateway) &&
        (c.distance === undefined || l.distance === undefined || c.distance === l.distance)
    );
    if (hit) {
      matched.add(hit);
      hit.inRoutingTable = true;
      hit.priority ??= l.priority;
      continue;
    }
    const c = compact({
      destination: l.destination,
      gateway: l.gateway,
      interface: l.interface,
      distance: l.distance,
      priority: l.priority,
      source: l.type === 'connect' ? 'connected' : l.type === 'static' ? 'static' : 'other',
      configured: false,
      liveType: l.type,
      inRoutingTable: true,
    }) as Candidate;
    matched.add(c);
    cands.push(c);
  }

  // States, one destination at a time.
  const byDest = new Map<string, Candidate[]>();
  for (const c of cands) byDest.set(c.destination, [...(byDest.get(c.destination) ?? []), c]);
  for (const group of byDest.values()) {
    const installed = group.filter((c) => c.inRoutingTable);
    const best = installed.reduce<Candidate | undefined>((b, c) => (!b || better(c, b) ? c : b), undefined);
    const winners = installed.filter((c) => best && sameRank(c, best));
    const names = winners.map((w) => w.interface ?? '?').join(', ');
    for (const c of group) {
      c.inRoutingTable ??= false;
      let st: CandidateState;
      if (c.inRoutingTable) {
        st = best && sameRank(c, best) ? { state: 'active' } : { state: 'standby', reason: `in the routing table, but ${names} wins with a lower priority` };
      } else {
        const why = blockedBy(c, signals);
        if (why) st = { state: 'inactive', reason: why };
        else if (best && !better(c, best))
          st = { state: 'standby', reason: `${names} wins with a lower ${rank(c)[0] > rank(best)[0] ? 'distance' : 'priority'}` };
        else st = { state: 'inactive', reason: 'not in the routing table; the reason is not visible in the data read' };
      }
      Object.assign(c, compact(st));
    }
  }
  return cands.sort(byDestination);
}

/** "Internet (0.0.0.0/0): wan2 active (distance 1); wan1 (distance 1) is down: ...; backup wan1 via 192.0.2.9 at distance 5." */
export function describePaths(cands: Candidate[], max = 30): { paths: string[]; more?: number } {
  const byDest = new Map<string, Candidate[]>();
  for (const c of cands) byDest.set(c.destination, [...(byDest.get(c.destination) ?? []), c]);
  const out: string[] = [];
  for (const [dest, group] of byDest) {
    // Only destinations with a choice of path, or a path that is not in use.
    if (group.length < 2 && group.every((c) => c.state === 'active' || c.state === undefined)) continue;
    if (group.every((c) => c.source === 'connected')) continue;
    const dupIface = (c: Candidate) => group.filter((x) => x.interface === c.interface).length > 1;
    const name = (c: Candidate) => `${c.interface ?? '?'}${c.gateway && dupIface(c) ? ` via ${c.gateway}` : ''}`;
    const at = (c: Candidate) => `distance ${c.distance ?? '?'}${group.some((x) => x !== c && x.distance === c.distance && x.priority !== c.priority) ? `, priority ${c.priority ?? 0}` : ''}`;
    const active = group.filter((c) => c.state === 'active');
    const label = dest === '0.0.0.0/0' ? 'Internet (0.0.0.0/0)' : dest;
    if (group.every((c) => c.state === undefined)) {
      out.push(`${label}: ${group.map((c) => `${name(c)} (${at(c)})`).join('; ')}; which is in use is not known (the live routing table was not read).`);
      continue;
    }
    const parts = [active.length ? `${active.map(name).join(' and ')} active (${at(active[0])})` : 'no path in use'];
    for (const c of group) {
      if (c.state === 'active') continue;
      const preferred = active.length > 0 && better(c, active[0]);
      if (c.state === 'inactive') parts.push(`${name(c)} (${at(c)}${preferred ? ', preferred' : ''}) is down: ${c.reason}`);
      else parts.push(`backup ${name(c)} at ${at(c)}`);
    }
    out.push(`${label}: ${parts.join('; ')}.`);
  }
  return out.length > max ? { paths: out.slice(0, max), more: out.length - max } : { paths: out };
}

// --- Summary -----------------------------------------------------------------------------------------

export type Failover = 'sdwan' | 'static-routes-with-link-monitor' | 'static-routes-distance-priority' | 'unknown';

const pathText = (c: Candidate) => `${c.interface ?? '?'}${c.gateway ? ` via ${c.gateway}` : ''} (distance ${c.distance ?? '?'}, priority ${c.priority ?? '?'})`;
const routeText = (r: StaticRoute) =>
  `${r.viaSdwan ? `SD-WAN${r.sdwanZones ? ` zone ${r.sdwanZones.join(', ')}` : ''}` : (r.interface ?? '?')}${r.gateway ? ` via ${r.gateway}` : ''}` +
  ` (distance ${r.distance ?? '?'}, priority ${r.priority ?? '?'})`;

function summarize(input: {
  statics?: StaticRoute[];
  staticGot: Got;
  lmGot: Got;
  monitors: (Raw & LinkMonitor)[];
  sdwanGot: Got;
  sdwan?: Sdwan;
  liveGot: Got;
  candidates: Candidate[];
}) {
  const { statics, staticGot, lmGot, monitors, sdwanGot, sdwan, liveGot, candidates } = input;
  const caveats: string[] = [];

  const enabledDefaults = (statics ?? []).filter(isDefaultRoute).filter((r) => enabled(r.status));
  const defaults = candidates.filter((c) => c.destination === '0.0.0.0/0' && !c.blackhole);
  const liveDefaults = defaults.filter((c) => c.inRoutingTable);
  const sdwanMembers = (sdwan?.members ?? []).filter((m) => enabled(m.status));
  // Live-only defaults from a routing protocol (BGP, OSPF...), not from the interface (DHCP, PPPoE) or config.
  const dynamicDefaults = defaults.filter((c) => !c.configured && c.liveType && !/^(static|dhcp|pppoe|connect|kernel)$/i.test(c.liveType));
  const dynamicTypes = [...new Set(dynamicDefaults.map((c) => c.liveType))].join(', ');

  if (!liveGot.ok) caveats.push(`The live routing table could not be read (${liveGot.fail.reason}), so which route is active is not known.`);
  else if (liveDefaults.length === 0) caveats.push('The live routing table has no default route (0.0.0.0/0).');
  if (liveGot.ok && liveGot.res.truncated) caveats.push('The live routing table was longer than this server reads; a route may be missing from it.');

  const updating = monitors.filter((m) => enabled(m.status) && m.updateStaticRoute !== 'disable');
  // Every interface that carries a default route (configured or live), SD-WAN members aside.
  const defaultIfaces = new Set(defaults.filter((c) => c.source !== 'sdwan' && enabled(c.status)).map((c) => c.interface).filter(Boolean));
  const routesUseSdwan = enabledDefaults.some((r) => r.viaSdwan);
  const sdwanOn = !!sdwan?.enabled && sdwanMembers.length > 0;
  const sdwanKnown = sdwanGot.ok || sdwanGot.fail.reason === 'not_supported';
  const lmKnown = lmGot.ok || lmGot.fail.reason === 'not_supported';
  // Monitors that can actually remove a default route (exemptions and their own route lists honoured).
  const lmOnDefaults = updating.filter((m) =>
    defaults.some((c) => enabled(c.status) && c.source !== 'sdwan' && monitorsFor(c, { monitors: [m], sdwanDown: new Map() }).length > 0)
  );
  const describeLm = (m: LinkMonitor) =>
    `${m.interface ?? '?'} (${m.name ?? '?'}${m.servers ? ` -> ${m.servers.join(', ')}` : ''}${m.protocol ? `, ${m.protocol}` : ''})`;
  const routeList = (rs: StaticRoute[]) => rs.map(routeText).join('; ');
  const reasonOf = (g: Got) => (g.ok ? '' : g.fail.reason);

  let failover: Failover;
  let summary: string;
  if (sdwanOn || routesUseSdwan) {
    failover = 'sdwan';
    const hcs = sdwan?.healthChecks ?? [];
    const hcText = hcs.length
      ? `${plural(hcs.length, 'health check')} (${hcs
          .map((h) => `${h.name ?? '?'}${h.server ? ` -> ${h.server}` : ''}${h.protocol ? ` ${h.protocol}` : ''} on ${h.members?.join(', ') ?? 'no members'}${h.updateStaticRoute === 'disable' ? ', update-static-route disabled' : ''}`)
          .join('; ')})`
      : 'no health checks, so a member is taken out only when its link goes down';
    summary = sdwan
      ? `SD-WAN (${sdwan.enabled ? 'enabled' : 'disabled'}) with ${plural(sdwanMembers.length, 'member')} (${sdwanMembers.map((m) => m.interface ?? '?').join(', ') || 'none'}) and ${hcText}.`
      : `SD-WAN: a static default route uses SD-WAN, but the SD-WAN settings could not be read (${reasonOf(sdwanGot)}).`;
    if (routesUseSdwan) summary += ` The default route uses SD-WAN: ${routeList(enabledDefaults.filter((r) => r.viaSdwan))}.`;
    else summary += ' No static default route points at SD-WAN, so SD-WAN may steer only some traffic; check the default routes below.';
    if (sdwan && !sdwan.enabled) summary += ' SD-WAN reads as disabled although a route points at it.';
    if (updating.length) summary += ` Link-monitors also update static routes on ${updating.map(describeLm).join(', ')}.`;
  } else if (!sdwanKnown) {
    failover = 'unknown';
    summary = `Unknown: the SD-WAN settings could not be read (${reasonOf(sdwanGot)}), so SD-WAN cannot be ruled out.`;
  } else if (!statics && !liveGot.ok) {
    failover = 'unknown';
    summary = 'Unknown: neither the static routes nor the live routing table could be read.';
  } else if (lmOnDefaults.length) {
    failover = 'static-routes-with-link-monitor';
    summary =
      `Static routes with link-monitor (update-static-route enabled on ${lmOnDefaults.map(describeLm).join(', ')}). ` +
      'When a monitored WAN stops answering, its static routes are removed and the next default route by distance and priority takes over.';
    if (enabledDefaults.length) summary += ` Default routes: ${routeList(enabledDefaults)}.`;
  } else if (!lmKnown) {
    failover = 'unknown';
    summary = `Unknown: SD-WAN is not in use, but the link-monitor settings could not be read (${reasonOf(lmGot)}), so static routes with or without link-monitor cannot be told apart.`;
  } else if (dynamicDefaults.length && !enabledDefaults.length) {
    failover = 'unknown';
    summary =
      `Not SD-WAN or link-monitor: the default route is learned by ${dynamicTypes} (a routing protocol), not configured. ` +
      'Failover follows that protocol, which can withdraw a route while the interface stays up.';
  } else if (defaults.some((c) => enabled(c.status))) {
    failover = 'static-routes-distance-priority';
    if (dynamicDefaults.length) caveats.push(`A default route is also learned by ${dynamicTypes} (a routing protocol); it can be withdrawn while its interface stays up.`);
    const paths = new Set(defaults.filter((c) => enabled(c.status)).map((c) => `${c.interface}|${c.gateway ?? ''}`)).size;
    summary =
      'Static routes by distance/priority only, no health check: a default route leaves the table only when its interface goes down, not when the ISP stops passing traffic.' +
      (enabledDefaults.length ? ` Default routes: ${routeList(enabledDefaults)}.` : ' The default route is learned on the interface (DHCP or PPPoE), not configured as a static route.') +
      (paths <= 1 ? ' There is only one default route, so there is no failover to another WAN by routing.' : '');
    if (!statics) caveats.push(`The static routes could not be read (${reasonOf(staticGot)}); this rests on the live routing table.`);
  } else {
    failover = 'unknown';
    summary = 'Unknown: no default route (0.0.0.0/0) was found in the static routes or the live routing table.';
  }
  const idle = updating.filter((m) => !m.interface || !defaultIfaces.has(m.interface));
  if (failover !== 'sdwan' && idle.length) caveats.push(`Link-monitor ${idle.map((m) => m.name ?? '?').join(', ')} updates static routes on an interface with no default route (${idle.map((m) => m.interface ?? '?').join(', ')}).`);
  const off = monitors.filter((m) => enabled(m.status) && m.updateStaticRoute === 'disable');
  if (off.length) caveats.push(`Link-monitor ${off.map((m) => m.name ?? '?').join(', ')} has update-static-route disabled, so it does not move routes.`);
  if (failover !== 'unknown' && !lmKnown) caveats.push(`The link-monitor settings could not be read (${reasonOf(lmGot)}).`);
  if (failover !== 'unknown' && !statics) caveats.push(`The static routes could not be read (${reasonOf(staticGot)}).`);

  const { paths, more } = describePaths(candidates);
  const active = defaults.filter((c) => c.state === 'active');
  return compact({
    failover,
    text: summary,
    paths: paths.length ? paths : undefined,
    pathsNote: more ? `${more} more destinations with backup or down paths are not described; see routeCandidates.` : undefined,
    activeDefaultRoute: active.length ? active.map(pathText).join('; ') : undefined,
    defaultRoutes: defaults.length ? defaults : undefined,
    caveats: caveats.length ? [...new Set(caveats)] : undefined,
  });
}


// --- The tool ----------------------------------------------------------------------------------------

async function getRouting(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const vdom = checkVdom(args.vdom);
  const maxRows = args.max_rows as number;
  const device = await deviceInfo(api, sn);
  const ctx: Ctx = { api, sn, vdom, meta: {}, answered: 0 };

  // The static routes go first, alone: if the device does not answer at all,
  // nothing else is tried (FortiGate Cloud allows few errors a minute). A 404
  // or a FortiOS permission error on this one read does not stop the rest.
  const staticGot = await get(ctx, 'staticRoutes', READ.static);
  if (!staticGot.ok && staticGot.fail.reason === 'rate_limited') throw ctx.rateLimit!;
  // A 404 for a serial FortiGate Cloud does not list is the device missing, not an old FortiOS:
  // every other read would 404 too and spend FortiGate Cloud's small error budget.
  const unknownDevice = !staticGot.ok && staticGot.fail.reason === 'not_supported' && !device.row.connection && !!device.note;
  const down = !staticGot.ok && (staticGot.deviceDown || unknownDevice);
  const skip = (read: string) =>
    notTried(
      read,
      unknownDevice
        ? `not tried: the ${READ.static} read answered 404 and this serial is not in the FortiGate Cloud device list`
        : `not tried: the ${READ.static} read failed, so the device is probably not reachable through FortiGate Cloud`
    );

  const [policyGot, lmGot, lmLiveGot, sdwanGot, hcGot, memGot, liveGot, ifGot, ipsecGot] = down
    ? [READ.policy, READ.lmConfig, READ.lmLive, READ.sdwan, READ.hcLive, READ.membersLive, READ.routesLive, READ.ifLive, READ.ipsecLive].map(skip)
    : await Promise.all([
        get(ctx, 'policyRoutes', READ.policy),
        get(ctx, 'linkMonitorConfig', READ.lmConfig),
        get(ctx, 'linkMonitorLive', READ.lmLive),
        readSdwan(ctx),
        get(ctx, 'sdwanHealthLive', READ.hcLive),
        get(ctx, 'sdwanMembersLive', READ.membersLive),
        get(ctx, 'routesLive', READ.routesLive),
        get(ctx, 'interfaceLive', READ.ifLive),
        get(ctx, 'ipsecLive', READ.ipsecLive),
      ]);
  // Nothing at all was read and FortiCloud is rate-limiting: the fleet policy's structured error.
  if (ctx.answered === 0 && ctx.rateLimit) throw ctx.rateLimit;

  const statics = staticGot.ok ? staticGot.res.rows.map(staticRoute) : undefined;
  const lmLive = groupByName(lmLiveGot.ok ? lmLiveGot.res.rows : []);
  const monitors: (Raw & LinkMonitor)[] = lmGot.ok ? lmGot.res.rows.map((m) => linkMonitorRow(m, lmLive.get(String(m.name ?? '')))) : [];
  const configuredNames = new Set(lmGot.ok ? lmGot.res.rows.map((m) => String(m.name ?? '')) : []);
  for (const [name, rows] of lmLive) if (!configuredNames.has(name)) monitors.push(compact({ name: text(name, 80), live: rows.map(probe) }) as Raw & LinkMonitor);
  const sd = sdwanSection(sdwanGot as Got & { legacy?: boolean }, hcGot, memGot, maxRows);

  // What the live reads say about each interface, tunnel and SD-WAN member, for the route states.
  const links = ifGot.ok ? new Map(ifGot.res.rows.filter((r) => typeof r.name === 'string' && typeof r.link === 'boolean').map((r) => [r.name as string, r.link as boolean])) : undefined;
  const tunnels = ipsecGot.ok
    ? new Map(ipsecGot.res.rows.filter((t) => typeof t.name === 'string').map((t) => [t.name as string, list(t.proxyid).some((p) => p.status === 'up')]))
    : undefined;
  const sdwanDown = new Map<string, string[]>();
  const hcConfig = new Map((sd.sdwan?.healthChecks ?? []).map((h) => [h.name, h]));
  for (const r of hcGot.ok ? hcGot.res.rows : []) {
    const iface = text(r.interface, 60);
    const name = text(r.name, 80) ?? '?';
    if (!iface || !/^(down|dead|error)$/i.test(String(r.status ?? ''))) continue;
    if (hcConfig.get(name)?.updateStaticRoute === 'disable') continue;
    sdwanDown.set(iface, [...(sdwanDown.get(iface) ?? []), name]);
  }
  const liveRoutes = liveGot.ok
    ? liveGot.res.rows.map((r) => compact({ destination: subnetText(r.ip_mask), gateway: addr(r.gateway), interface: text(r.interface, 60), distance: num(r.distance), priority: num(r.priority), type: text(r.type, 20) }) as LiveRoute)
    : undefined;
  const candidates = buildCandidates({ statics, sdwan: sd.sdwan, live: liveRoutes, signals: { monitors, links, tunnels, sdwanDown } });

  const all = [staticGot, policyGot, lmGot, lmLiveGot, sdwanGot, hcGot, memGot, liveGot, ifGot, ipsecGot];
  const unread = all.filter((g): g is Extract<Got, { ok: false }> => !g.ok).map((g) => g.fail);
  const truncated = all.filter((g) => g.ok && (g.res.truncated || g.res.nestedCut)).map((g) => g.read);

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
    complete: unread.length || truncated.length ? false : undefined,
    unreadable: unread.length ? unread.map((f) => compact({ read: f.read, reason: f.reason, retryAfterSeconds: f.retryAfterSeconds })) : undefined,
    truncatedReads: truncated.length ? truncated : undefined,
    rateLimited: ctx.rateLimit
      ? {
          retryAfterSeconds: ctx.rateLimit.retryAfterSeconds,
          note: `FortiCloud rate-limited a read, so no further reads were made; the reads marked rate_limited are missing. Try again in ${ctx.rateLimit.retryAfterSeconds} s for them.`,
        }
      : undefined,
    summary: summarize({ statics, staticGot, lmGot, monitors, sdwanGot, sdwan: sd.sdwan, liveGot, candidates }),
    routeCandidates: compact({
      source: liveGot.ok
        ? `derived: ${READ.static} (SD-WAN routes expanded per member) merged with the installed routes of ${READ.routesLive}; FortiOS has no documented REST read of the routing-table database`
        : `configured routes only (${READ.static}): the live routing table could not be read, so no route has a state`,
      stateFrom: [lmLiveGot, hcGot, ifGot, ipsecGot].filter((g) => g.ok).map((g) => g.read),
      interfaceLiveError: ifGot.ok ? undefined : ifGot.fail,
      ipsecLiveError: ipsecGot.ok ? undefined : ipsecGot.fail,
      ...cutInfo([
        [ifGot.read, ifGot.ok ? ifGot.res : undefined],
        [ipsecGot.read, ipsecGot.ok ? ipsecGot.res : undefined],
      ]),
      note: 'Every path per destination, sorted by destination then distance. state: active = installed and preferred; standby = valid, but a lower distance or priority route wins; inactive = out of the table, with the likely reason.',
      total: candidates.length,
      ...shownInfo(candidates.length, Math.min(candidates.length, maxRows), MORE),
      routes: candidates.slice(0, maxRows),
    }),
    staticRoutes: staticSection(staticGot, statics, maxRows),
    policyRoutes: policySection(policyGot, maxRows),
    linkMonitors: linkMonitorSection(lmGot, lmLiveGot, monitors),
    sdwan: sd.section,
  });
}

export const ROUTING_SPECS: ToolSpec[] = [
  {
    name: 'forticloud_get_routing',
    description:
      "How one FortiGate routes and fails over between WANs, read live from the device through FortiGate Cloud (read-only FortiOS API): configured static routes (destination, gateway, interface, distance, priority, weight, SD-WAN zone, blackhole, dynamic gateway, link-monitor exempt), policy routes, link monitors (configured: interface, servers, protocol, interval, failtime, recoverytime, update-static-route; live: alive/dead, latency, jitter, packet loss), and SD-WAN (configured: status, zones, members, health checks with SLA targets, rules; live: health-check state per member and member state; 'virtual-wan-link' on FortiOS 6.2 and older). routeCandidates lists every path per destination like `get router info routing-table database` (configured static and SD-WAN routes merged with the live table's connected and installed routes), each active, standby (a lower distance or priority wins) or inactive with the likely reason (disabled, link-monitor dead, SD-WAN health check down, interface or tunnel down). The summary says whether WAN failover is done by SD-WAN, by static routes with link-monitor, or by distance/priority alone, and says per default route and per remote subnet which path is in use and which are backups or down. Each read reports on its own when it is not supported, denied, rate limited or truncated. Never returns passwords, keys or certificates.",
    params: {
      serial: { type: 'string', description: 'The FortiGate serial number, e.g. FGT60FTK00000000.', required: true, maxLength: 40 },
      max_rows: { type: 'int', description: 'Most static routes, policy routes and SD-WAN rules listed (1-500).', min: 1, max: 500, default: 50 },
      vdom: { type: 'string', description: 'The VDOM, on a FortiGate with VDOMs (default: the root VDOM).', maxLength: 31 },
    },
    run: getRouting,
  },
];
