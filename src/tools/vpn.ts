import type { Api } from '../client.js';
import { MAX_NESTED } from '../fortios.js';
import { checkSerial, timeIn } from './format.js';
import { maskOf, parseFortiosNet, parseIpv4, subnetText } from './ip.js';
import type { Net } from './ip.js';
import { checkVdom, cutInfo, deviceInfo, shownInfo } from './network.js';
import { get, notTried, staticRoute } from './routing.js';
import type { Ctx, Got, StaticRoute } from './routing.js';
import { clean, compact, num } from './shared.js';
import type { ToolSpec } from './spec.js';

/**
 * forticloud_get_vpn: whether one FortiGate's IPsec VPN failover is set up
 * right and would take over. Per tunnel: the phase 1 failover settings (backup
 * of which primary via `monitor`, hold-down, DPD, idle timeout,
 * auto-negotiate, ADVPN), the phase 2 selectors, the live state (up, partially
 * up or down, per phase 2, with byte counters), the static routes over it and
 * the BGP neighbors over it. Then the primary/backup pairs, and one plain line
 * per remote site saying whether failover should work.
 *
 * Every read is reported on its own (not supported, denied, rate limited,
 * failed), like forticloud_get_routing; after a 429 no further read is
 * started. Pre-shared keys and certificates are never read off the answer
 * (src/fortios.ts allowlists).
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
const enabled = (status: unknown) => status !== 'disable';

/** The reads this tool makes, by the label each section reports. */
const READ = {
  phase1: 'cmdb vpn.ipsec/phase1-interface',
  phase2: 'cmdb vpn.ipsec/phase2-interface',
  live: 'monitor vpn/ipsec',
  static: 'cmdb router/static',
  interfaces: 'cmdb system/interface',
  sdwanMembers: 'monitor virtual-wan/members',
  bgp: 'cmdb router/bgp',
  bgpLive: 'monitor router/bgp/neighbors',
  ssl: 'cmdb vpn.ssl/settings',
  sslLive: 'monitor vpn/ssl',
} as const;

const MORE = 'raise max_rows to see them';
/** Most phase 2 selectors listed per tunnel (as in forticloud_get_network). */
const MAX_PHASE2_SHOWN = 50;
/** Most site lines in the summary. */
const MAX_SITES = 30;

// --- Tunnels -----------------------------------------------------------------------------------------

export type TunnelStatus = 'up' | 'partially up' | 'down';

interface Phase2 {
  name?: string;
  local?: string;
  remote?: string;
  autoNegotiate?: string;
  keepalive?: string;
  state?: string;
  incomingBytes?: number;
  outgoingBytes?: number;
  expiresInSeconds?: number;
}

interface TunnelRoute {
  seq?: number;
  destination: string;
  gateway?: string;
  distance?: number;
  priority?: number;
  status?: string;
  vrf?: number;
  comment?: string;
}

export interface Tunnel {
  name: string;
  configured: boolean;
  type?: string;
  interface?: string;
  remoteGateway?: string;
  ikeVersion?: string;
  modeCfg?: string;
  /** This tunnel is the backup of these (phase 1 `monitor`). */
  backupOf?: string[];
  monitorMin?: number;
  holdDown?: { type?: string; delaySeconds?: number; time?: string; weekday?: string };
  dpd?: { mode?: string; retryCount?: number; retryIntervalSeconds?: number | string };
  idleTimeout?: { enabled: boolean; minutes?: number };
  autoNegotiate?: string;
  natKeepaliveSeconds?: number;
  netDevice?: string;
  addRoute?: string;
  routeDistance?: number;
  routePriority?: number;
  exchangeInterfaceIp?: string;
  advpn?: Raw;
  comment?: string;
  sdwanMember?: true;
  status?: TunnelStatus;
  statusNote?: string;
  phase2Up?: number;
  phase2Count?: number;
  live?: Raw;
  phase2?: Phase2[];
  phase2Total?: number;
  phase2Note?: string;
  routes?: TunnelRoute[];
  bgpNeighbors?: string[];
  /** BGP neighbors over this tunnel that are shut down (shutdown, or admin down): listed, but they carry no routes. */
  bgpNeighborsShutdown?: string[];
}

const side = (p: Raw, pre: 'src' | 'dst') => {
  const type = text(p[`${pre}-addr-type`], 20);
  if (type === 'name') return text(p[`${pre}-name`], 80);
  if (type === 'range') return `${addr(p[`${pre}-start-ip`]) ?? '?'} - ${addr(p[`${pre}-end-ip`]) ?? '?'}`;
  return subnetText(p[`${pre}-subnet`]);
};
const liveSubnets = (p: Raw, a: string, b: string) => {
  const s = [...list(p[a]), ...list(p[b])].map((x) => subnetText(x.subnet)).filter((x): x is string => !!x);
  return s.length ? s.join(', ') : undefined;
};

function phase1Settings(p1: Raw): Omit<Tunnel, 'name' | 'configured'> {
  const backupOf = names(p1.monitor);
  const holdType = text(p1['monitor-hold-down-type'], 20);
  const dpdMode = text(p1.dpd, 20);
  const interval = num(p1['dpd-retryinterval']) ?? text(p1['dpd-retryinterval'], 20);
  const advpn = compact({
    sender: text(p1['auto-discovery-sender'], 10),
    receiver: text(p1['auto-discovery-receiver'], 10),
    forwarder: text(p1['auto-discovery-forwarder'], 10),
    shortcuts: text(p1['auto-discovery-shortcuts'], 20),
  });
  const advpnOn = Object.values(advpn).some((v) => v === 'enable');
  return compact({
    type: text(p1.type, 20),
    interface: text(p1.interface, 60),
    remoteGateway: addr(p1['remote-gw']) ?? text(p1['remotegw-ddns'], 120),
    ikeVersion: text(p1['ike-version'], 4),
    modeCfg: text(p1['mode-cfg'], 10),
    backupOf: backupOf.length ? backupOf : undefined,
    monitorMin: backupOf.length ? num(p1['monitor-min']) : undefined,
    holdDown: backupOf.length
      ? compact({
          type: holdType,
          delaySeconds: holdType === 'delay' ? num(p1['monitor-hold-down-delay']) : undefined,
          time: holdType === 'time' ? text(p1['monitor-hold-down-time'], 10) : undefined,
          weekday: holdType === 'time' ? text(p1['monitor-hold-down-weekday'], 12) : undefined,
        })
      : undefined,
    dpd: dpdMode !== undefined || p1['dpd-retrycount'] !== undefined ? compact({ mode: dpdMode, retryCount: num(p1['dpd-retrycount']), retryIntervalSeconds: interval }) : undefined,
    idleTimeout: p1['idle-timeout'] !== undefined ? compact({ enabled: on(p1['idle-timeout']), minutes: on(p1['idle-timeout']) ? num(p1['idle-timeoutinterval']) : undefined }) : undefined,
    autoNegotiate: text(p1['auto-negotiate'], 10),
    natKeepaliveSeconds: num(p1.keepalive),
    netDevice: text(p1['net-device'], 10),
    addRoute: text(p1['add-route'], 10),
    routeDistance: on(p1['add-route']) ? num(p1.distance) : undefined,
    routePriority: on(p1['add-route']) ? num(p1.priority) : undefined,
    exchangeInterfaceIp: text(p1['exchange-interface-ip'], 10),
    advpn: advpnOn ? advpn : undefined,
    comment: text(p1.comments, 200),
  }) as Omit<Tunnel, 'name' | 'configured'>;
}

/** Up when every phase 2 is up, partially up when some are, down when none is. */
function statusOf(up: number, total: number): TunnelStatus {
  if (total > 0 && up === total) return 'up';
  return up > 0 ? 'partially up' : 'down';
}

function buildTunnels(p1Got: Got, p2Got: Got, liveGot: Got): Tunnel[] {
  // A phase 2 config list that is cut or could not be read may leave out a selector that is not
  // negotiated (in neither list).
  const p2ConfigCut = !p2Got.ok || !!(p2Got.res.truncated || p2Got.res.nestedCut);
  const p2ByP1 = new Map<string, Raw[]>();
  for (const p of p2Got.ok ? p2Got.res.rows : []) {
    const k = String(p.phase1name ?? '');
    p2ByP1.set(k, [...(p2ByP1.get(k) ?? []), p]);
  }
  const live = new Map<string, Raw>();
  for (const t of liveGot.ok ? liveGot.res.rows : []) if (typeof t.name === 'string') live.set(t.name, t);
  const used = new Set<string>();
  // A cut answer: a tunnel missing from it may be up, so its state is unknown, not down.
  const listCut = liveGot.ok && !!liveGot.res.truncated;

  const tunnel = (name: string, p1: Raw | undefined): Tunnel => {
    const settings: Partial<Tunnel> = p1 ? phase1Settings(p1) : {};
    const l = live.get(name);
    if (l) used.add(name);
    const configuredP2 = p2ByP1.get(name) ?? [];
    const liveP2 = list(l?.proxyid);
    // Its phase 2 list was cut at MAX_NESTED: a selector missing from it may be up.
    const p2Cut = liveP2.length >= MAX_NESTED;
    const byName = new Map(liveP2.map((p) => [String(p.p2name ?? ''), p]));
    const liveOf = (p: Raw | undefined) =>
      p
        ? compact({
            state: text(p.status, 10),
            liveLocal: liveSubnets(p, 'proxy_src', 'proxysrc'),
            liveRemote: liveSubnets(p, 'proxy_dst', 'proxydst'),
            incomingBytes: num(p.incoming_bytes),
            outgoingBytes: num(p.outgoing_bytes),
            expiresInSeconds: num(p.expire),
          })
        : {};
    const seen = new Set<string>();
    const phase2: Phase2[] = configuredP2.map((p) => {
      const n = String(p.name ?? '');
      seen.add(n);
      const lp = byName.get(n);
      return compact({
        name: text(p.name, 80),
        local: side(p, 'src'),
        remote: side(p, 'dst'),
        autoNegotiate: text(p['auto-negotiate'], 10),
        keepalive: text(p.keepalive, 10),
        // A configured selector the live read does not list has not been negotiated (unless the list was cut).
        ...(lp ? liveOf(lp) : liveGot.ok && (l ? !p2Cut : !listCut) ? { state: 'not negotiated' } : {}),
      }) as Phase2;
    });
    for (const lp of liveP2) if (!seen.has(String(lp.p2name ?? ''))) phase2.push(compact({ name: text(lp.p2name, 80), ...liveOf(lp) }) as Phase2);

    let status: TunnelStatus | undefined;
    let statusNote: string | undefined;
    let phase2Up: number | undefined;
    let phase2Count: number | undefined;
    let liveInfo: Raw | undefined;
    // Dial-up (type dynamic) servers show one live entry per connected peer: name_0, name_1...
    const dialup = settings.type === 'dynamic';
    const instances = dialup ? [...live.entries()].filter(([n]) => n.startsWith(`${name}_`) && /^\d+$/.test(n.slice(name.length + 1))) : [];
    if (liveGot.ok) {
      if (l && !dialup) {
        phase2Up = phase2.filter((p) => p.state === 'up').length;
        phase2Count = phase2.filter((p) => p.state !== undefined).length;
        // A configured selector the cut live list leaves out may be up or down: the aggregate is unknown.
        const unknownP2 = phase2.length - phase2Count;
        if (unknownP2 > 0 && p2Cut) {
          status = undefined;
          statusNote = `state unknown: ${phase2Up} of ${phase2Count} phase 2 selector(s) read are up, ${unknownP2} not in the part of the live list read (it was cut)`;
        } else if (p2ConfigCut && phase2Up === phase2Count) {
          status = undefined;
          statusNote = `state unknown: the ${phase2Up} phase 2 selector(s) read are up, but the phase 2 configuration could not be read in full, so a selector that is not negotiated may be missing`;
        } else status = statusOf(phase2Up, phase2Count);
        liveInfo = compact({
          remoteGateway: addr(l.rgwy),
          incomingBytes: num(l.incoming_bytes),
          outgoingBytes: num(l.outgoing_bytes),
          creationTime: num(l.creation_time),
          connections: num(l.connection_count),
        });
      } else if (dialup) {
        for (const [n] of instances) used.add(n);
        const upPeers = [...instances.map(([, x]) => x), ...(l ? [l] : [])].filter((x) => list(x.proxyid).some((p) => p.status === 'up')).length;
        status = upPeers ? 'up' : listCut ? undefined : 'down';
        statusNote = upPeers ? `dial-up: ${plural(upPeers, 'peer')} connected` : listCut ? 'dial-up: no connected peer in the part of the live list read (the answer was cut)' : 'dial-up: no peer connected';
        liveInfo = compact({ dialupPeers: instances.length, dialupPeersUp: upPeers });
      } else if (listCut) {
        statusNote = 'state unknown: not in the part of the live tunnel list read (the answer was cut)';
      } else {
        status = 'down';
        statusNote = 'not in the live tunnel list';
      }
    }
    return compact({
      name: text(name, 80) ?? name,
      configured: !!p1,
      ...settings,
      type: settings.type ?? text(l?.type, 20),
      remoteGateway: (liveInfo?.remoteGateway as string | undefined) ?? settings.remoteGateway,
      comment: settings.comment ?? text(l?.comments, 200),
      status,
      statusNote,
      phase2Up: status === 'partially up' ? phase2Up : undefined,
      phase2Count: status === 'partially up' ? phase2Count : undefined,
      live: liveInfo && Object.keys(liveInfo).length ? liveInfo : undefined,
      phase2: phase2.length ? phase2.slice(0, MAX_PHASE2_SHOWN) : undefined,
      phase2Total: phase2.length > MAX_PHASE2_SHOWN ? phase2.length : undefined,
      phase2Note: phase2.length > MAX_PHASE2_SHOWN ? `${phase2.length - MAX_PHASE2_SHOWN} more phase 2 selectors not shown (at most ${MAX_PHASE2_SHOWN} per tunnel)` : undefined,
    }) as Tunnel;
  };

  const out: Tunnel[] = [];
  const configured = new Set<string>();
  for (const p1 of p1Got.ok ? p1Got.res.rows : []) {
    const name = String(p1.name ?? '');
    if (!name) continue;
    configured.add(name);
    out.push(tunnel(name, p1));
  }
  // Live entries with no phase 1 of their own (phase 1 unreadable) and not a dial-up instance.
  for (const name of live.keys()) if (!used.has(name) && !configured.has(name)) out.push(tunnel(name, undefined));
  return out;
}

// --- BGP ---------------------------------------------------------------------------------------------

interface TunnelNet {
  ip?: Net;
  remote?: Net;
}

const contains = (net: Net, ip: number) => ((ip & maskOf(net.prefix)) >>> 0) === ((net.ip & maskOf(net.prefix)) >>> 0);

type NeighborRef = { ip?: string; interface?: string; updateSource?: string; localIp?: string };

/** The tunnel a BGP neighbor runs over: its interface or update-source, else its address in the tunnel's subnet. */
function tunnelFor(n: NeighborRef, tunnels: Set<string>, nets: Map<string, TunnelNet>): string | undefined {
  if (n.interface && tunnels.has(n.interface)) return n.interface;
  if (n.updateSource && tunnels.has(n.updateSource)) return n.updateSource;
  const ip = parseIpv4(n.ip);
  const local = parseIpv4(n.localIp);
  // Exact addresses first (the peer is a tunnel's remote end, or the session runs from a tunnel's
  // own address), then the subnets, so overlapping tunnel subnets cannot win over an exact match.
  for (const [name, t] of nets) if (ip !== undefined && t.remote && t.remote.ip === ip) return name;
  for (const [name, t] of nets) if (local !== undefined && t.ip && t.ip.ip === local) return name;
  for (const [name, t] of nets) {
    if (ip !== undefined && t.remote && t.remote.prefix < 32 && contains(t.remote, ip)) return name;
    if (ip !== undefined && t.ip && t.ip.prefix <= 31 && contains(t.ip, ip) && t.ip.ip !== ip) return name;
  }
  return undefined;
}

interface Neighbor extends Raw {
  ip?: string;
  tunnel?: string;
  state?: string;
}

function bgpSection(cfgGot: Got, liveGot: Got, tunnelNames: Set<string>, nets: Map<string, TunnelNet>): { section: Raw; neighbors: Neighbor[] } {
  const cfg = cfgGot.ok ? (cfgGot.res.rows[0] ?? {}) : undefined;
  const live = new Map<string, Raw>();
  for (const r of liveGot.ok ? liveGot.res.rows : []) {
    const ip = text(r.neighbor_ip, 60);
    if (ip) live.set(ip, r);
  }
  const groups = list(cfg?.['neighbor-group']).map((g) =>
    compact({ name: text(g.name, 80), remoteAs: text(g['remote-as'], 20) ?? num(g['remote-as']), interface: text(g.interface, 60), updateSource: text(g['update-source'], 60) })
  );
  const ranges = list(cfg?.['neighbor-range']).map((r) => ({ prefix: parseFortiosNet(r.prefix), prefixText: subnetText(r.prefix), group: text(r['neighbor-group'], 80) }));
  const liveOf = (l: Raw | undefined) =>
    l
      ? compact({
          state: text(l.state, 30),
          adminStatus: typeof l.admin_status === 'boolean' ? (l.admin_status ? 'up' : 'down') : text(l.admin_status, 20),
          localIp: addr(l.local_ip),
          uptime: num(l.uptime) ?? num(l.up_time) ?? text(l.uptime, 40) ?? text(l.up_time, 40),
          prefixesReceived: num(l.prefixes_received) ?? num(l.received_prefixes),
        })
      : {};
  const seen = new Set<string>();
  const neighbors: Neighbor[] = list(cfg?.neighbor).map((n) => {
    const ip = text(n.ip, 60);
    if (ip) seen.add(ip);
    const l = ip ? live.get(ip) : undefined;
    const base = compact({
      ip,
      remoteAs: text(n['remote-as'], 20) ?? num(n['remote-as']),
      interface: text(n.interface, 60),
      updateSource: text(n['update-source'], 60),
      description: text(n.description, 120),
      shutdown: on(n.shutdown) || undefined,
      bfd: text(n.bfd, 10),
      ...liveOf(l),
    }) as Neighbor;
    return compact({ ...base, tunnel: tunnelFor(base as NeighborRef, tunnelNames, nets), state: base.state ?? (liveGot.ok ? 'not in the live neighbor list' : undefined) }) as Neighbor;
  });
  // Live neighbors not configured one by one: dynamic peers from a neighbor range (ADVPN hubs).
  for (const [ip, l] of live) {
    if (seen.has(ip)) continue;
    const n = parseIpv4(ip);
    const range = n === undefined ? undefined : ranges.find((r) => r.prefix && contains(r.prefix, n));
    const group = range ? groups.find((g) => g.name === range.group) : undefined;
    const base = compact({ ip, remoteAs: num(l.remote_as) ?? text(l.remote_as, 20), dynamic: true, neighborGroup: group?.name, interface: group?.interface, updateSource: group?.updateSource, ...liveOf(l) }) as Neighbor;
    neighbors.push(compact({ ...base, tunnel: tunnelFor(base as NeighborRef, tunnelNames, nets) }) as Neighbor);
  }
  const shown = neighbors.slice(0, 200);
  const section = compact({
    source: compact({ configured: cfgGot.ok ? cfgGot.read : undefined, live: liveGot.ok ? liveGot.read : undefined }),
    configuredError: cfgGot.ok ? undefined : cfgGot.fail,
    liveError: liveGot.ok ? undefined : liveGot.fail,
    ...cutInfo([
      [cfgGot.read, cfgGot.ok ? cfgGot.res : undefined],
      [liveGot.read, liveGot.ok ? liveGot.res : undefined],
    ]),
    as: text(cfg?.as, 20) ?? num(cfg?.as),
    routerId: addr(cfg?.['router-id']),
    total: neighbors.length,
    overTunnels: neighbors.filter((n) => n.tunnel).length,
    ...shownInfo(neighbors.length, shown.length, 'at most 200 neighbors are listed'),
    neighbors: shown,
    neighborGroups: groups.length ? groups.slice(0, 50) : undefined,
    neighborRanges: ranges.length ? ranges.slice(0, 50).map((r) => compact({ prefix: r.prefixText, neighborGroup: r.group })) : undefined,
    note:
      neighbors.length
        ? 'tunnel: the IPsec tunnel the neighbor runs over (its interface or update-source, or its address in the tunnel interface subnet). FortiOS documents no uptime or prefix count on monitor router/bgp/neighbors; they show only when the device returns them.'
        : undefined,
  });
  if (!cfgGot.ok && !liveGot.ok) return { section: { ...cfgGot.fail, ...section }, neighbors };
  return { section, neighbors };
}

// --- SSL-VPN -----------------------------------------------------------------------------------------

function sslSection(cfgGot: Got, liveGot: Got) {
  const cfg = cfgGot.ok ? (cfgGot.res.rows[0] ?? {}) : undefined;
  const ifaces = names(cfg?.['source-interface']);
  const status = text(cfg?.status, 10);
  // FortiOS before 7.4 has no status field: SSL-VPN listens when it has a source interface.
  const isOn = cfg ? (status ? on(status) : ifaces.length > 0) : undefined;
  const section = compact({
    source: compact({ configured: cfgGot.ok ? cfgGot.read : undefined, live: liveGot.ok ? liveGot.read : undefined }),
    configuredError: cfgGot.ok ? undefined : cfgGot.fail,
    liveError: liveGot.ok ? undefined : liveGot.fail,
    ...cutInfo([
      [cfgGot.read, cfgGot.ok ? cfgGot.res : undefined],
      [liveGot.read, liveGot.ok ? liveGot.res : undefined],
    ]),
    enabled: isOn,
    port: num(cfg?.port),
    listensOn: ifaces.length ? ifaces : undefined,
    usersConnected: liveGot.ok ? liveGot.res.rows.length : undefined,
    note: 'Only whether SSL-VPN is on and how many users are connected; no user names or addresses are read.',
  });
  if (!cfgGot.ok && !liveGot.ok) return { ...cfgGot.fail, ...section };
  return section;
}

// --- Pairs and sites ---------------------------------------------------------------------------------

export interface Pair {
  primary: string;
  backup: string;
  backupOnlyWhenPrimaryDown: boolean;
  holdDown?: string;
  primaryState?: string;
  backupState?: string;
  state: string;
  healthy?: boolean;
  problems?: string[];
}

interface Facts {
  byName: Map<string, Tunnel>;
  /** The static routes could be read (so "no route" can be said). */
  routesKnown: boolean;
  /** SD-WAN membership could be read (or SD-WAN is not on this FortiOS). */
  sdwanKnown: boolean;
  liveKnown: boolean;
  /** The phase 1 list was complete, so a tunnel missing from it is not configured. */
  phase1Complete: boolean;
  /** The phase 2 list was complete, so a tunnel's selectors are all known. */
  phase2Complete: boolean;
  /** BGP neighbors were read completely (or BGP is not on this FortiOS), so a tunnel with none has none. */
  bgpKnown: boolean;
}

const stateWord = (t: Tunnel | undefined) =>
  !t ? 'not configured' : t.status === undefined ? 'state unknown' : t.status === 'partially up' ? `partially up (${t.phase2Up} of ${t.phase2Count} phase 2 up)` : t.status;

const dpdText = (t: Tunnel) => {
  const d = t.dpd;
  if (!d?.mode) return 'DPD not reported';
  if (d.mode === 'disable') return 'DPD off';
  return `DPD ${d.mode}${d.retryCount !== undefined && d.retryIntervalSeconds !== undefined ? ` ${d.retryCount}x${d.retryIntervalSeconds}s` : ''}`;
};

const holdText = (t: Tunnel) => {
  const h = t.holdDown;
  if (!h?.type) return undefined;
  if (h.type === 'delay') return `fails back ${h.delaySeconds ?? '?'} s after the primary returns`;
  if (h.type === 'time') return `fails back at ${h.time ?? '?'}${h.weekday && h.weekday !== 'everyday' ? ` on ${h.weekday}` : ''}`;
  return h.type === 'immediate' ? 'fails back at once' : `hold-down ${h.type}`;
};

const liveRoutes = (t: Tunnel | undefined) => (t?.routes ?? []).filter((r) => enabled(r.status));

/** One of these routes covers r: same VRF and the same destination, or a subnet that contains it. */
/** A route destination as a network; unlike parseFortiosNet, keeps 0.0.0.0/0 (the default route). */
function routeNet(dst: string): { ip: number; prefix: number } | undefined {
  const d = dst.trim();
  if (d === '0.0.0.0/0' || d === '0.0.0.0 0.0.0.0' || d === '0.0.0.0') return { ip: 0, prefix: 0 };
  return parseFortiosNet(dst);
}

function coveredBy(routes: TunnelRoute[], r: TunnelRoute): boolean {
  const same = routes.filter((x) => (x.vrf ?? 0) === (r.vrf ?? 0));
  if (same.some((x) => x.destination === r.destination)) return true;
  const rn = routeNet(r.destination);
  if (!rn) return false;
  const nets = same.map((x) => routeNet(x.destination)).filter((n): n is { ip: number; prefix: number } => !!n);
  // Several narrower routes may cover it together (two /25s make a /24): split it in halves until each
  // part is inside one route or outside all of them. Too many splits to tell counts as covered, so a
  // large route table never raises a false alarm.
  const budget = { n: 4096 };
  const cover = (t: { ip: number; prefix: number }): boolean => {
    if (nets.some((x) => x.prefix <= t.prefix && contains(x, t.ip))) return true;
    const touching = nets.filter((x) => (x.prefix <= t.prefix ? contains(x, t.ip) : contains(t, x.ip)));
    if (!touching.length) return false;
    if (t.prefix >= 32 || --budget.n <= 0) return true;
    const lo = { ip: t.ip, prefix: t.prefix + 1 };
    const hi = { ip: (t.ip | (1 << (31 - t.prefix))) >>> 0, prefix: t.prefix + 1 };
    return cover(lo) && cover(hi);
  };
  return cover(rn);
}

/** Why this tunnel carries traffic (a route, SD-WAN, BGP or routes it adds itself), or undefined. */
function carries(t: Tunnel): string | undefined {
  if (liveRoutes(t).length) return 'static routes';
  if (t.sdwanMember) return 'SD-WAN';
  if (t.bgpNeighbors?.length) return 'BGP';
  if (t.addRoute === 'enable' && t.type === 'dynamic') return 'add-route';
  return undefined;
}

const DPD_OFF = (t: string, role: string) =>
  `DPD is off on ${role}${t}: a dead tunnel is noticed only when its interface goes down or IKE renegotiates, so failover is slow or never happens`;

/** The routing checks (static routes, SD-WAN, BGP) ran on complete data. */
const routingKnown = (f: Facts) => f.routesKnown && f.sdwanKnown && f.bgpKnown;
const ROUTING_UNKNOWN = 'the routes or phase 2 selectors could not be checked in full, so whether the tunnels carry the traffic is not known';

/** The remote subnets of a tunnel's configured phase 2 selectors, or undefined when they are not all known
 * (the phase 2 list incomplete, more selectors than shown, or a selector given as an address name or range). */
/** Two networks share addresses: one contains the other. A route only partly inside a selector still
 * carries the part the selector lets through, so overlap (not containment) is the test. */
const overlaps = (a: { ip: number; prefix: number }, b: { ip: number; prefix: number }) =>
  a.prefix <= b.prefix ? contains(a, b.ip) : contains(b, a.ip);

function selectorNets(t: Tunnel, f: Facts): { ip: number; prefix: number }[] | undefined {
  if (!f.phase2Complete || t.phase2Total !== undefined || !t.phase2?.length) return undefined;
  const nets = t.phase2.map((p) => (p.remote ? routeNet(p.remote) : undefined));
  return nets.every((n) => !!n) ? (nets as { ip: number; prefix: number }[]) : undefined;
}

type Net4 = { ip: number; prefix: number };
/** A tunnel's configured selectors as local and remote networks, or undefined when they are not all known. */
function selectorPairs(t: Tunnel, f: Facts): { local: Net4; remote: Net4; text: string }[] | undefined {
  if (!f.phase2Complete || t.phase2Total !== undefined || !t.phase2?.length) return undefined;
  const out: { local: Net4; remote: Net4; text: string }[] = [];
  for (const p of t.phase2) {
    const local = p.local ? routeNet(p.local) : undefined;
    const remote = p.remote ? routeNet(p.remote) : undefined;
    if (!local || !remote) return undefined;
    out.push({ local, remote, text: `${p.local} -> ${p.remote}` });
  }
  return out;
}

const containsNet = (a: Net4, b: Net4) => a.prefix <= b.prefix && contains(a, b.ip);
const halves = (n: Net4): [Net4, Net4] => [
  { ip: n.ip, prefix: n.prefix + 1 },
  { ip: (n.ip | (1 << (31 - n.prefix))) >>> 0, prefix: n.prefix + 1 },
];
/** Do these selectors together cover all traffic from local to remote? true, false, or undefined when it
 * would take too many splits to tell. Splits the wider side in halves until each part is inside one
 * selector or outside all of them. */
function selectorsCover(sels: { local: Net4; remote: Net4 }[], local: Net4, remote: Net4, budget = { n: 4096 }): boolean | undefined {
  if (sels.some((y) => containsNet(y.local, local) && containsNet(y.remote, remote))) return true;
  const touching = sels.filter((y) => overlaps(y.local, local) && overlaps(y.remote, remote));
  if (!touching.length) return false;
  if (--budget.n <= 0 || (local.prefix >= 32 && remote.prefix >= 32)) return undefined;
  const splitLocal = local.prefix < 32 && (local.prefix <= remote.prefix || remote.prefix >= 32);
  const parts = splitLocal ? halves(local).map((l) => [l, remote] as const) : halves(remote).map((r) => [local, r] as const);
  let unknown = false;
  for (const [l, r] of parts) {
    const c = selectorsCover(touching, l, r, budget);
    if (c === false) return false;
    if (c === undefined) unknown = true;
  }
  return unknown ? undefined : true;
}
/** The narrower of two overlapping networks (their intersection). */
const narrower = (a: Net4, b: Net4) => (a.prefix >= b.prefix ? a : b);

function analysePair(primaryName: string, b: Tunnel, f: Facts): Pair {
  const p = f.byName.get(primaryName);
  const problems: string[] = [];
  const hold = holdText(b);
  // Missing from a cut phase 1 list: it may be configured further down.
  const primaryOmitted = !p && !f.phase1Complete;
  let selectorsUnknown = false;
  if (!p && !primaryOmitted) problems.push(`backup ${b.name} is set to monitor ${primaryName}, which is not configured, so it never takes over from anything`);
  if (p?.dpd?.mode === 'disable') problems.push(DPD_OFF(p.name, 'primary '));
  if (f.routesKnown && f.sdwanKnown && f.bgpKnown && !carries(b)) problems.push(`backup ${b.name} has no route using it: it will come up but carry no traffic`);
  if (p && f.routesKnown && f.sdwanKnown && f.bgpKnown && !carries(p)) problems.push(`primary ${p.name} has no route using it`);
  // A backup with BGP still has its phase 2 selectors checked; only the static route check is skipped,
  // since BGP can bring the routes it lacks.
  const backupBgp = !!b.bgpNeighbors?.length;
  if (p && f.routesKnown && f.sdwanKnown && f.bgpKnown && !b.sdwanMember && (backupBgp || liveRoutes(b).length)) {
    // A backup route covers a primary destination when it is in the same VRF and its subnet contains it.
    const missing = backupBgp ? [] : liveRoutes(p).filter((r) => !coveredBy(liveRoutes(b), r)).map((r) => r.destination);
    if (missing.length) problems.push(`backup ${b.name} has no route to ${[...new Set(missing)].join(', ')}, which the primary carries`);
    // The backup's phase 2 selectors must let that traffic through too.
    const sels = selectorNets(b, f);
    if (!sels) selectorsUnknown = true;
    else {
      const outside = liveRoutes(p)
        .filter((r) => coveredBy(liveRoutes(b), r))
        .filter((r) => {
          const rn = routeNet(r.destination);
          return !!rn && !sels.some((n) => overlaps(n, rn));
        })
        .map((r) => r.destination);
      if (outside.length) problems.push(`backup ${b.name}'s phase 2 selectors do not include ${[...new Set(outside)].join(', ')}, which the primary carries: that traffic cannot use the backup`);
    }
    // Each primary selector needs a backup selector whose local and remote sides both overlap it.
    const pSel = selectorPairs(p, f);
    const bSel = selectorPairs(b, f);
    if (!pSel || !bSel) selectorsUnknown = true;
    else {
      // Only selectors for subnets the primary routes: a selector with no route carries no traffic to fail over.
      const routed = liveRoutes(p).map((r) => routeNet(r.destination)).filter((n): n is Net4 => !!n);
      const unmatched: string[] = [];
      // Only the routed part of each primary selector has to be covered: its remote side clipped to
      // each destination the primary routes.
      for (const x of pSel)
        for (const n of routed.filter((n) => overlaps(n, x.remote))) {
          const c = selectorsCover(bSel, x.local, narrower(x.remote, n));
          if (c === false) unmatched.push(x.text);
          else if (c === undefined) selectorsUnknown = true;
        }
      if (unmatched.length) problems.push(`backup ${b.name}'s phase 2 selectors do not cover all of the primary's ${[...new Set(unmatched)].join(', ')}: that traffic cannot use the backup`);
    }
  }

  const unknownOf = [p, b].filter((t): t is Tunnel => !!t && t.status === undefined).map((t) => t.name);
  let state = f.liveKnown
    ? `unknown: the live state of ${unknownOf.join(' and ')} is not known (the live answer was cut)`
    : 'unknown: the live tunnel state could not be read';
  let healthy: boolean | undefined;
  let backupState = stateWord(b);
  // The backup comes up when monitor-min of its monitored primaries are down (0 or unset: all of them).
  const monitored = (b.backupOf ?? [primaryName]).map((n) => f.byName.get(n));
  const total = monitored.length;
  const multi = total > 1;
  const allKnown = monitored.every((t) => !!t && t.status !== undefined);
  const downCount = monitored.filter((t) => t?.status === 'down').length;
  const threshold = b.monitorMin && b.monitorMin > 0 ? Math.min(b.monitorMin, total) : total;
  const shouldActivate = downCount >= threshold;
  const activation = `it comes up when ${threshold === total ? (total > 1 ? `all ${total}` : 'the primary') : `${threshold} of ${total}`} monitored ${total > 1 ? 'primaries are' : 'primary is'} down`;
  if (multi && p && p.status && b.status && allKnown) {
    const pUp = p.status !== 'down';
    const bUp = b.status !== 'down';
    if (!shouldActivate && !bUp) {
      state = pUp ? 'primary up, backup idle' : 'primary down, backup idle';
      backupState = 'idle';
      if (!pUp) problems.push(`primary ${p.name} is down; ${total - downCount} of ${total} monitored primaries are still up, so backup ${b.name} stays idle (${activation})`);
    } else if (shouldActivate && bUp) {
      state = pUp ? `primary up, backup up (${downCount} of ${total} monitored primaries down)` : 'failed over: primary down, backup up';
      if (!pUp) problems.push(`primary ${p.name} is down: traffic is on the backup`);
    } else if (shouldActivate && !bUp) {
      state = 'backup down when needed';
      problems.push(`backup ${b.name} is down although ${downCount} of ${total} monitored primaries are down (${activation})`);
    } else {
      state = 'both up';
      problems.push(`backup ${b.name} is up while only ${downCount} of ${total} monitored primaries are down (${activation})${hold ? `; expected during the hold-down (${hold})` : ''}`);
    }
    if (p.status === 'partially up')
      problems.push(`primary ${p.name} is only partly up (${p.phase2Up} of ${p.phase2Count} phase 2 up): the down selectors have no path unless the backup comes up`);
    if (b.status === 'partially up' && shouldActivate) problems.push(`backup ${b.name} is only partly up (${b.phase2Up} of ${b.phase2Count} phase 2 up)`);
    // No problem found is 'healthy' only when the routing checks ran on complete data.
    healthy = problems.length ? false : routingKnown(f) && !selectorsUnknown ? true : undefined;
  } else if (multi && p && !allKnown) {
    const names = b.backupOf ?? [primaryName];
    const unk = names.filter((_, i) => !monitored[i] || monitored[i]!.status === undefined);
    state = `unknown: the live state of ${unk.join(' and ') || b.name} is not known, so whether ${b.name} should be up is not known`;
  } else if (p && p.status && b.status) {
    const pUp = p.status !== 'down';
    const bUp = b.status !== 'down';
    if (p.status === 'up' && !bUp) {
      state = 'primary up, backup idle';
      backupState = 'idle';
    } else if (!pUp && b.status === 'up') {
      state = 'failed over: primary down, backup up';
      problems.push(`primary ${p.name} is down: traffic is on the backup`);
    } else if (!pUp && !bUp) {
      state = 'both down';
      problems.push(`both ${p.name} and ${b.name} are down: no tunnel to this site`);
    } else if (pUp && bUp) {
      state = 'both up';
      problems.push(
        b.holdDown?.type === 'delay' || b.holdDown?.type === 'time'
          ? `backup ${b.name} is up while the primary is up: expected only during the hold-down after the primary came back (${hold})`
          : `backup ${b.name} is up while the primary is up: with monitor it should stay down; expected only for a moment after the primary came back`
      );
    } else {
      state = `primary ${stateWord(p)}, backup ${stateWord(b)}`;
    }
    if (p.status === 'partially up')
      problems.push(`primary ${p.name} is only partly up (${p.phase2Up} of ${p.phase2Count} phase 2 up): the backup stays idle while any of the primary is up, so the down selectors have no path`);
    if (b.status === 'partially up' && !pUp) problems.push(`backup ${b.name} is only partly up (${b.phase2Up} of ${b.phase2Count} phase 2 up)`);
    // No problem found is 'healthy' only when the routing checks ran on complete data.
    healthy = problems.length ? false : routingKnown(f) && !selectorsUnknown ? true : undefined;
  } else if (primaryOmitted) {
    state = `unknown: ${primaryName} is not in the part of the phase 1 list read (it was cut)`;
  } else if (!p) {
    state = 'no primary';
    healthy = false;
  }
  return compact({
    primary: primaryName,
    backup: b.name,
    backupOnlyWhenPrimaryDown: !!p || primaryOmitted,
    holdDown: hold,
    primaryState: primaryOmitted ? 'not in the part of the phase 1 list read' : stateWord(p),
    backupState,
    state,
    healthy: healthy ?? (problems.length ? false : undefined),
    problems: problems.length ? problems : undefined,
  }) as Pair;
}

/** "172.16.70.0/24 distance 10/15" per destination over the group's tunnels (in group order). */
function routesText(group: Tunnel[]): string | undefined {
  const byDst = new Map<string, { t: string; d?: number }[]>();
  for (const t of group) for (const r of liveRoutes(t)) byDst.set(r.destination, [...(byDst.get(r.destination) ?? []), { t: t.name, d: r.distance }]);
  if (!byDst.size) return undefined;
  const parts = [...byDst.entries()].slice(0, 5).map(([dst, rs]) => {
    const tunnels = new Set(rs.map((r) => r.t));
    const only = group.length > 1 && tunnels.size < group.length ? ` (only via ${[...tunnels].join(', ')})` : '';
    return `${dst} distance ${rs.map((r) => r.d ?? '?').join('/')}${only}`;
  });
  return `routes ${parts.join(', ')}${byDst.size > 5 ? ` and ${byDst.size - 5} more` : ''}`;
}

/** A neighbor shut down in the config, or reported admin down: it carries no routes. */
const isShut = (n: Neighbor) => n.shutdown === true || n.adminStatus === 'down';

const bgpText = (group: Tunnel[], neighbors: Neighbor[]) => {
  const over = neighbors.filter((n) => n.tunnel && group.some((t) => t.name === n.tunnel));
  return over.length ? `BGP ${over.slice(0, 4).map((n) => `${n.ip} over ${n.tunnel} ${isShut(n) ? 'shut down' : (n.state ?? 'state unknown')}`).join(', ')}${over.length > 4 ? ` and ${over.length - 4} more` : ''}` : undefined;
};

export type SiteMethod = 'monitor' | 'routing' | 'sdwan' | 'single';

interface Site {
  tunnels: string[];
  method: SiteMethod;
  line: string;
  problems: string[];
}

/** Tunnels grouped per remote site: monitor pairs, tunnels with routes to the same subnet, and the SD-WAN members. */
function sites(tunnels: Tunnel[], f: Facts, neighbors: Neighbor[]): { sites: Site[]; pairs: Pair[] } {
  const parent = new Map<string, string>(tunnels.map((t) => [t.name, t.name]));
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r)!;
    return r;
  };
  const union = (a: string, b: string) => {
    if (parent.has(a) && parent.has(b)) parent.set(find(a), find(b));
  };
  const inPair = new Set<string>();
  for (const t of tunnels)
    for (const p of t.backupOf ?? []) {
      union(t.name, p);
      inPair.add(t.name);
      inPair.add(p);
    }
  const byDst = new Map<string, string[]>();
  for (const t of tunnels) for (const r of liveRoutes(t)) byDst.set(`${r.vrf ?? 0}|${r.destination}`, [...(byDst.get(`${r.vrf ?? 0}|${r.destination}`) ?? []), t.name]);
  for (const ts of byDst.values()) for (const t of ts.slice(1)) union(ts[0], t);
  const sdwan = tunnels.filter((t) => t.sdwanMember && !inPair.has(t.name));
  for (const t of sdwan.slice(1)) union(sdwan[0].name, t.name);

  const groups = new Map<string, Tunnel[]>();
  for (const t of tunnels) groups.set(find(t.name), [...(groups.get(find(t.name)) ?? []), t]);

  const out: Site[] = [];
  const pairs: Pair[] = [];
  for (const g of groups.values()) {
    // Primaries first, then their backups.
    g.sort((a, b) => Number(!!a.backupOf?.length) - Number(!!b.backupOf?.length));
    const label = g.map((t) => t.name).join(' / ');
    const extra = [routesText(g), bgpText(g, neighbors)].filter(Boolean).join('; ');
    const tail = (problems: string[], ok: string) => (problems.length ? `Problems: ${problems.join('; ')}.` : ok);
    const backups = g.filter((t) => t.backupOf?.length);
    if (backups.length) {
      const ps = backups.flatMap((b) => b.backupOf!.map((p) => analysePair(p, b, f)));
      pairs.push(...ps);
      const problems = [...new Set(ps.flatMap((p) => p.problems ?? []))];
      const prim = g.filter((t) => !t.backupOf?.length);
      const desc = [
        ...prim.map((p) => `primary ${p.name} ${stateWord(p)} (${dpdText(p)})`),
        ...backups.map((b) => {
          const st = ps.find((p) => p.backup === b.name)?.backupState ?? stateWord(b);
          return `backup ${b.name} ${st} (monitor of ${b.backupOf!.join(', ')}${holdText(b) ? `, ${holdText(b)}` : ''})`;
        }),
      ].join('; ');
      const ok = ps.every((p) => p.healthy)
        ? 'Failover should work.'
        : ps.some((p) => p.state.startsWith('unknown'))
          ? 'Failover is set up; the live state is not known, so whether it would take over now is not known.'
          : `Failover is set up and the tunnels look right now, but ${ROUTING_UNKNOWN}.`;
      out.push({ tunnels: g.map((t) => t.name), method: 'monitor', line: `${label}: ${desc}${extra ? `; ${extra}` : ''}. ${tail(problems, ok)}`, problems });
      continue;
    }
    if (g.length > 1 && g.every((t) => t.sdwanMember)) {
      const desc = g.map((t) => `${t.name} ${stateWord(t)}`).join(', ');
      out.push({
        tunnels: g.map((t) => t.name),
        method: 'sdwan',
        line: `SD-WAN members ${desc}${extra ? `; ${extra}` : ''}. Failover between them is SD-WAN's (health checks and SLA): see forticloud_get_routing.`,
        problems: [],
      });
      continue;
    }
    if (g.length > 1) {
      // No monitor: every tunnel stays up and the routes' distances pick one.
      const problems: string[] = [];
      for (const t of g) if (t.dpd?.mode === 'disable') problems.push(DPD_OFF(t.name, ''));
      const up = g.filter((t) => t.status !== undefined && t.status !== 'down');
      if (g.every((t) => t.status === 'down')) problems.push(`all of ${label} are down: no tunnel to this site`);
      // Each subnet needs a route over more than one tunnel, or nothing takes over when its tunnel fails.
      let selUnknown = false;
      // A tunnel can carry a destination when it has a covering route and its selectors include it.
      const passes = (o: Tunnel, r: TunnelRoute) => {
        const sels = selectorNets(o, f);
        if (!sels) {
          selUnknown = true;
          return true;
        }
        const rn = routeNet(r.destination);
        return !rn || sels.some((n) => overlaps(n, rn));
      };
      if (f.routesKnown && f.sdwanKnown && f.bgpKnown) {
        const via = new Map<string, { dst: string; route: TunnelRoute; tunnels: Set<string> }>();
        for (const t of g)
          for (const r of liveRoutes(t)) {
            const k = `${r.vrf ?? 0}|${r.destination}`;
            const e = via.get(k) ?? { dst: r.destination, route: r, tunnels: new Set<string>() };
            e.tunnels.add(t.name);
            via.set(k, e);
          }
        const only = new Map<string, string[]>();
        for (const { dst, route } of via.values()) {
          // The tunnels that can carry it: a covering route (a wider subnet in the same VRF counts) and
          // phase 2 selectors that include it.
          const carriers = g.filter((o) => coveredBy(liveRoutes(o), route) && passes(o, route));
          if (!carriers.length) {
            const routed = g.filter((o) => coveredBy(liveRoutes(o), route)).map((o) => o.name);
            problems.push(`${dst} is routed via ${routed.join(', ')}, but no tunnel's phase 2 selectors include it: that traffic has no path`);
            continue;
          }
          if (carriers.length > 1) {
            // Each carrier's selectors for this destination must be covered by another carrier's, on the
            // local side too, or traffic from that local subnet has no other tunnel.
            const dn = routeNet(dst);
            for (const c of carriers) {
              const mine = selectorPairs(c, f);
              if (!mine || !dn) {
                selUnknown = true;
                continue;
              }
              for (const x of mine.filter((x) => overlaps(x.remote, dn))) {
                const remote = narrower(x.remote, dn);
                let covered: boolean | undefined = false;
                for (const o of carriers) {
                  if (o === c) continue;
                  const theirs = selectorPairs(o, f);
                  const r = theirs ? selectorsCover(theirs, x.local, remote) : undefined;
                  if (r === true) {
                    covered = true;
                    break;
                  }
                  if (r === undefined) covered = undefined;
                }
                if (covered === undefined) selUnknown = true;
                else if (!covered) problems.push(`traffic ${x.text} has a path only via ${c.name}: no other tunnel's phase 2 selectors cover it`);
              }
            }
            continue;
          }
          const t = carriers[0].name;
          // BGP over another tunnel of the site may carry a backup route the static routes do not show.
          if (g.some((o) => o.name !== t && o.bgpNeighbors?.length)) continue;
          only.set(t, [...(only.get(t) ?? []), dst]);
        }
        for (const [t, dsts] of only)
          problems.push(`${dsts.join(', ')} ${dsts.length === 1 ? 'has' : 'have'} a route only via ${t}: no other tunnel takes over if it goes down`);
      }
      for (const t of g) if (t.status === 'partially up') problems.push(`${t.name} is only partly up (${t.phase2Up} of ${t.phase2Count} phase 2 up)`);
      for (const t of g) if (t.status === 'down' && up.length) problems.push(`${t.name} is down: the site is reached over ${up.map((u) => u.name).join(', ')}`);
      const desc = g.map((t) => `${t.name} ${stateWord(t)} (${dpdText(t)})`).join('; ');
      const allKnown = g.every((t) => t.status !== undefined);
      const ok = !f.liveKnown ? 'Failover is by route distance; the live state could not be read.' : !allKnown ? `Failover is by route distance; the live state of ${g.filter((t) => t.status === undefined).map((t) => t.name).join(', ')} is not known, so whether it would take over is not known.` : !routingKnown(f) || selUnknown ? `Failover is by route distance, but ${ROUTING_UNKNOWN}.` : 'Failover by route distance should work: when a tunnel goes down its routes leave the table and the next one takes over.';
      out.push({
        tunnels: g.map((t) => t.name),
        method: 'routing',
        line: `${label}: ${desc}; no monitor: every tunnel stays up and the route distance picks one${extra ? `; ${extra}` : ''}. ${tail([...new Set(problems)], ok)}`,
        problems: [...new Set(problems)],
      });
      continue;
    }
    const t = g[0];
    if (t.sdwanMember) {
      out.push({ tunnels: [t.name], method: 'sdwan', line: `${t.name}: ${stateWord(t)}; SD-WAN member${extra ? `; ${extra}` : ''}. Failover is SD-WAN's (health checks and SLA): see forticloud_get_routing.`, problems: [] });
      continue;
    }
    const problems: string[] = [];
    if (t.status === 'down' && t.type !== 'dynamic') problems.push(`${t.name} is down`);
    if (t.status === 'partially up') problems.push(`${t.name} is only partly up (${t.phase2Up} of ${t.phase2Count} phase 2 up)`);
    out.push({
      tunnels: [t.name],
      method: 'single',
      line: `${t.name}: ${stateWord(t)}${t.statusNote ? ` (${t.statusNote})` : ''}; no backup tunnel${extra ? `; ${extra}` : ''}.${problems.length ? ` Problems: ${problems.join('; ')}.` : ''}`,
      problems,
    });
  }
  // Sites with problems first.
  out.sort((a, b) => Number(b.problems.length > 0) - Number(a.problems.length > 0));
  return { sites: out, pairs };
}

// --- The tool ----------------------------------------------------------------------------------------

async function getVpn(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const vdom = checkVdom(args.vdom);
  const maxRows = args.max_rows as number;
  const wanted = typeof args.tunnel === 'string' ? args.tunnel : undefined;
  const device = await deviceInfo(api, sn);
  const ctx: Ctx = { api, sn, vdom, meta: {}, answered: 0 };

  // Phase 1 goes first, alone: if the device does not answer at all, nothing
  // else is tried (FortiGate Cloud allows few errors a minute).
  const p1Got = await get(ctx, 'vpnPhase1', READ.phase1);
  if (!p1Got.ok && p1Got.fail.reason === 'rate_limited') throw ctx.rateLimit!;
  const unknownDevice = !p1Got.ok && p1Got.fail.reason === 'not_supported' && !device.row.connection && !!device.note;
  const down = !p1Got.ok && (p1Got.deviceDown || unknownDevice);
  const skip = (read: string) =>
    notTried(
      read,
      unknownDevice
        ? `not tried: the ${READ.phase1} read answered 404 and this serial is not in the FortiGate Cloud device list`
        : `not tried: the ${READ.phase1} read failed, so the device is probably not reachable through FortiGate Cloud`
    );
  const [p2Got, liveGot, staticGot, ifGot, memGot, bgpGot, bgpLiveGot, sslGot, sslLiveGot] = down
    ? [READ.phase2, READ.live, READ.static, READ.interfaces, READ.sdwanMembers, READ.bgp, READ.bgpLive, READ.ssl, READ.sslLive].map(skip)
    : await Promise.all([
        get(ctx, 'vpnPhase2', READ.phase2),
        get(ctx, 'vpnIpsecLive', READ.live),
        get(ctx, 'staticRoutes', READ.static),
        get(ctx, 'interfaceConfig', READ.interfaces),
        get(ctx, 'sdwanMembersLive', READ.sdwanMembers),
        get(ctx, 'bgpConfig', READ.bgp),
        get(ctx, 'bgpLive', READ.bgpLive),
        get(ctx, 'sslVpnConfig', READ.ssl),
        get(ctx, 'sslVpnLive', READ.sslLive),
      ]);
  if (ctx.answered === 0 && ctx.rateLimit) throw ctx.rateLimit;

  const tunnels = buildTunnels(p1Got, p2Got, liveGot);
  const byName = new Map(tunnels.map((t) => [t.name, t]));
  const tunnelNames = new Set(byName.keys());

  // Static routes over each tunnel (SD-WAN routes go through SD-WAN members, not the tunnel itself).
  const statics: StaticRoute[] = staticGot.ok ? staticGot.res.rows.map(staticRoute) : [];
  for (const r of statics) {
    const t = r.interface && !r.viaSdwan ? byName.get(r.interface) : undefined;
    if (!t) continue;
    t.routes = [
      ...(t.routes ?? []),
      compact({ seq: r.seq, destination: r.destinationAddress ?? r.destination, gateway: r.gateway, distance: r.distance, priority: r.priority, status: r.status, vrf: r.vrf as number | undefined, comment: r.comment as string | undefined }) as TunnelRoute,
    ];
  }
  // SD-WAN members (live; the membership only: get_routing has the health checks and SLA).
  if (memGot.ok)
    for (const m of memGot.res.rows) {
      const t = byName.get(text(m.interface, 60) ?? text(m.name, 60) ?? '');
      if (t) t.sdwanMember = true;
    }
  // Tunnel interface addresses, to match BGP neighbors to tunnels.
  const nets = new Map<string, TunnelNet>();
  if (ifGot.ok)
    for (const i of ifGot.res.rows) {
      const name = String(i.name ?? '');
      if (!tunnelNames.has(name)) continue;
      nets.set(name, { ip: parseFortiosNet(i.ip), remote: parseFortiosNet(i['remote-ip']) });
    }
  const bgp = bgpSection(bgpGot, bgpLiveGot, tunnelNames, nets);
  for (const n of bgp.neighbors) {
    const t = n.tunnel ? byName.get(n.tunnel) : undefined;
    if (!t || !n.ip) continue;
    if (isShut(n)) t.bgpNeighborsShutdown = [...(t.bgpNeighborsShutdown ?? []), n.ip];
    else t.bgpNeighbors = [...(t.bgpNeighbors ?? []), n.ip];
  }

  const facts: Facts = {
    byName,
    // A capped answer may have left the routes or members out: absence from it proves nothing.
    routesKnown: staticGot.ok && !staticGot.res.truncated && !staticGot.res.nestedCut,
    sdwanKnown: memGot.ok ? !memGot.res.truncated && !memGot.res.nestedCut : memGot.fail.reason === 'not_supported',
    liveKnown: liveGot.ok,
    phase1Complete: p1Got.ok && !p1Got.res.truncated,
    phase2Complete: p2Got.ok && !p2Got.res.truncated && !p2Got.res.nestedCut,
    bgpKnown: (() => {
      const whole = (g: Got) => g.ok && !g.res.truncated && !g.res.nestedCut;
      const cfg = bgpGot.ok ? whole(bgpGot) : bgpGot.fail.reason === 'not_supported';
      const live = bgpLiveGot.ok ? whole(bgpLiveGot) : true;
      // A neighbor with no interface or update-source is matched to a tunnel by the tunnel addresses.
      const byAddress = bgp.neighbors.some((n) => !n.tunnel && !n.interface && !n.updateSource);
      return (cfg || whole(bgpLiveGot)) && live && (!byAddress || whole(ifGot));
    })(),
  };
  const all = sites(tunnels, facts, bgp.neighbors);

  // The optional tunnel filter: the named tunnel and the tunnels of its site.
  let filter: Raw | undefined;
  let shownSites = all.sites;
  let shownPairs = all.pairs;
  let shownTunnels = tunnels;
  if (wanted) {
    const match = tunnels.find((t) => t.name.toLowerCase() === wanted.toLowerCase());
    const site = match ? all.sites.find((s) => s.tunnels.includes(match.name)) : undefined;
    const keep = new Set(site?.tunnels ?? []);
    shownSites = site ? [site] : [];
    shownPairs = all.pairs.filter((p) => keep.has(p.primary) || keep.has(p.backup));
    shownTunnels = tunnels.filter((t) => keep.has(t.name));
    filter = compact({
      tunnel: wanted,
      matched: match ? [...keep] : undefined,
      note: match
        ? keep.size > 1
          ? `Shows ${match.name} and the other tunnels to the same site.`
          : undefined
        : `No IPsec tunnel is named ${wanted}. Tunnels: ${tunnels.slice(0, 50).map((t) => t.name).join(', ') || 'none'}${tunnels.length > 50 ? ', ...' : ''}.`,
    });
  }

  const reads = [p1Got, p2Got, liveGot, staticGot, ifGot, memGot, bgpGot, bgpLiveGot, sslGot, sslLiveGot];
  const unread = reads.filter((g): g is Extract<Got, { ok: false }> => !g.ok).map((g) => g.fail);
  const truncated = reads.filter((g) => g.ok && (g.res.truncated || g.res.nestedCut)).map((g) => g.read);

  const caveats: string[] = [];
  if (!liveGot.ok) caveats.push(`The live tunnel state could not be read (${liveGot.fail.reason}), so whether a tunnel is up, and whether failover would take over now, is not known.`);
  if (!staticGot.ok) caveats.push(`The static routes could not be read (${staticGot.fail.reason}), so "no route uses this tunnel" is not checked.`);
  if (staticGot.ok && !facts.routesKnown) caveats.push('The static route list was cut, so "no route uses this tunnel" is not checked.');
  if (memGot.ok && !facts.sdwanKnown) caveats.push('The SD-WAN member list was cut, so "no route uses this tunnel" is not checked.');
  if (!facts.sdwanKnown && !memGot.ok) caveats.push(`SD-WAN membership could not be read (${memGot.fail.reason}), so "no route uses this tunnel" is not checked.`);
  if ((bgpGot.ok || bgpLiveGot.ok) && !facts.bgpKnown) caveats.push('Not every BGP neighbor could be placed on a tunnel (a BGP list was cut, or the tunnel addresses could not be read in full), so "no route uses this tunnel" is not checked.');
  if (!bgpGot.ok && !bgpLiveGot.ok && !facts.bgpKnown) caveats.push(`BGP could not be read (${bgpGot.fail.reason}), so "no route uses this tunnel" is not checked.`);
  else if (!ifGot.ok) caveats.push(`The tunnel interface addresses could not be read (${ifGot.fail.reason}), so BGP neighbors are matched to tunnels by interface and update-source only.`);
  if (shownSites.some((s) => s.problems.some((p) => /no route/.test(p))))
    caveats.push('Policy routes are not read; a tunnel used only by a policy route is reported with no route (forticloud_get_routing lists them).');
  if (tunnels.length === 0 && p1Got.ok) caveats.push('No IPsec phase 1 interfaces are configured (policy-based tunnels, vpn ipsec phase1, are not read).');

  const counts = (ts: Tunnel[]) => {
    const by = (s: TunnelStatus) => ts.filter((t) => t.status === s).length;
    const unknown = ts.filter((t) => t.status === undefined).length;
    return liveGot.ok ? `${plural(ts.length, 'IPsec tunnel')} (${by('up')} up, ${by('partially up')} partially up, ${by('down')} down${unknown ? `, ${unknown} unknown` : ''})` : plural(ts.length, 'IPsec tunnel');
  };
  const problemCount = shownSites.reduce((n, s) => n + s.problems.length, 0);
  const sitesShown = shownSites.slice(0, MAX_SITES);

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
    filter,
    summary: compact({
      text: `${counts(shownTunnels)}, ${plural(shownPairs.length, 'primary/backup pair')} (phase 1 monitor), ${plural(problemCount, 'problem')}.`,
      sites: sitesShown.map((s) => s.line),
      sitesNote: shownSites.length > MAX_SITES ? `${shownSites.length - MAX_SITES} more sites not described; see pairs and tunnels.` : undefined,
      caveats: caveats.length ? caveats : undefined,
      seeAlso: 'forticloud_get_routing shows which route to each remote subnet is active and the SD-WAN health checks and SLA.',
    }),
    pairs: shownPairs,
    tunnels: !p1Got.ok && !liveGot.ok
      ? { ...p1Got.fail, liveError: liveGot.fail }
      : compact({
          source: compact({
            configured: p1Got.ok ? `${READ.phase1} + ${p2Got.ok ? 'phase2-interface' : 'phase2-interface (not read)'}` : undefined,
            live: liveGot.ok ? READ.live : undefined,
            routes: staticGot.ok ? READ.static : undefined,
            sdwanMembers: memGot.ok ? READ.sdwanMembers : undefined,
          }),
          configuredError: p1Got.ok ? undefined : p1Got.fail,
          phase2Error: p2Got.ok ? undefined : p2Got.fail,
          liveError: liveGot.ok ? undefined : liveGot.fail,
          routesError: staticGot.ok ? undefined : staticGot.fail,
          sdwanMembersError: memGot.ok ? undefined : memGot.fail,
          interfacesError: ifGot.ok ? undefined : ifGot.fail,
          ...cutInfo([
            [p1Got.read, p1Got.ok ? p1Got.res : undefined],
            [p2Got.read, p2Got.ok ? p2Got.res : undefined],
            [liveGot.read, liveGot.ok ? liveGot.res : undefined],
            [staticGot.read, staticGot.ok ? staticGot.res : undefined],
            [ifGot.read, ifGot.ok ? ifGot.res : undefined],
          ]),
          note: shownTunnels.length
            ? 'status: up = every phase 2 up; partially up = some; down = none. backupOf: the phase 1 monitor setting (this tunnel comes up only when that one is down). live.creationTime is as FortiOS reports it. routes: the static routes whose interface is this tunnel.'
            : undefined,
          total: shownTunnels.length,
          ...shownInfo(shownTunnels.length, Math.min(shownTunnels.length, maxRows), MORE),
          tunnels: shownTunnels.slice(0, maxRows),
        }),
    bgp: bgp.section,
    sslVpn: sslSection(sslGot, sslLiveGot),
  });
}

export const VPN_SPECS: ToolSpec[] = [
  {
    name: 'forticloud_get_vpn',
    description:
      "Whether one FortiGate's IPsec VPN failover is set up right and would take over, read live from the device through FortiGate Cloud (read-only FortiOS API). Per tunnel: phase 1 (interface, remote gateway, type, IKE version, mode-cfg, monitor = this tunnel is the backup of that primary, monitor hold-down, DPD mode/retry count/interval, idle timeout, auto-negotiate, keepalive, net-device, add-route, exchange-interface-ip, ADVPN), phase 2 selectors with auto-negotiate and keepalive, live state (up, partially up or down, per phase 2, bytes in and out), the static routes over it (distance, priority) and the BGP neighbors over it (state). pairs: each primary/backup pair from monitor, its state (primary up and backup idle is healthy) and problems (both down, backup up while the primary is up, DPD off on the primary, no route using the backup). summary.sites: one plain line per remote site saying whether failover should work. Also BGP neighbors (remote AS, interface, state) and SSL-VPN (on or off, users connected). SD-WAN member tunnels are flagged; their health checks and SLA are in forticloud_get_routing. Each read reports on its own when it is not supported, denied, rate limited or truncated. Never returns pre-shared keys, certificates or passwords.",
    params: {
      serial: { type: 'string', description: 'The FortiGate serial number, e.g. FGT60FTK00000000.', required: true, maxLength: 40 },
      tunnel: { type: 'string', description: 'Only this IPsec tunnel (phase 1 name) and the other tunnels to the same site (its primary or backup).', maxLength: 35 },
      max_rows: { type: 'int', description: 'Most tunnels listed (1-500).', min: 1, max: 500, default: 50 },
      vdom: { type: 'string', description: 'The VDOM, on a FortiGate with VDOMs (default: the root VDOM).', maxLength: 31 },
    },
    run: getVpn,
  },
];
