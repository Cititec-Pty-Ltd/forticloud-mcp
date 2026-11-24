/**
 * FortiOS REST API reads through FortiGate Cloud's proxy
 * (`{FORTICLOUD_FGT_URL}/fgt/{serial}/api/v2/...`), read-only.
 *
 * Only GET, only the fixed endpoints below, and only the fields on each
 * endpoint's allowlist ever leave the client. A FortiOS answer carries
 * hundreds of fields, some of them secrets (PPPoE passwords, 802.1X keys,
 * IPsec pre-shared keys, certificates); anything not named here is dropped,
 * so a field FortiOS adds later is dropped too. There is no denylist.
 */

type Raw = Record<string, unknown>;

/**
 * Fields kept from one object. `true` keeps a scalar (string, number or
 * boolean); a nested Shape keeps an object, or each object in a list, with
 * its own allowlist. Anything else (other keys, objects where a scalar is
 * expected) is dropped.
 */
export interface Shape {
  [field: string]: true | Shape;
}

export interface FortiosEndpoint {
  /** Path under /api/v2/. */
  path: string;
  /** How `results` comes back: a list of objects, or an object keyed by name (monitor system/interface). */
  results: 'list' | 'map';
  /** Fixed query parameters (never caller-supplied). */
  query?: Record<string, string>;
  fields: Shape;
  /** Most entries kept from `results`. */
  maxItems: number;
}

/** Longest string kept from any field. */
const MAX_STRING = 300;

/**
 * The FortiOS endpoints the proxy helper can reach. Paths per the FortiOS
 * REST API reference (7.0-7.6); monitor and cmdb system/interface are
 * confirmed through the FortiGate Cloud proxy.
 */
export const FORTIOS_ENDPOINTS = {
  /** Configured interfaces: type, VLAN, parent, role, addressing. */
  interfaceConfig: {
    path: 'cmdb/system/interface',
    results: 'list',
    maxItems: 500,
    fields: {
      name: true,
      vdom: true,
      type: true,
      vlanid: true,
      interface: true,
      role: true,
      mode: true,
      ip: true,
      'remote-ip': true,
      status: true,
      alias: true,
      description: true,
      allowaccess: true,
      macaddr: true,
      speed: true,
      mtu: true,
      secondaryip: { id: true, ip: true },
      member: { 'interface-name': true },
    },
  },
  /** Live interface state: IP, link, speed, MAC, counters. `results` is keyed by interface name. */
  interfaceLive: {
    path: 'monitor/system/interface',
    results: 'map',
    query: { include_vlan: 'true', include_aggregate: 'true' },
    maxItems: 500,
    fields: {
      id: true,
      name: true,
      alias: true,
      mac: true,
      ip: true,
      mask: true,
      link: true,
      speed: true,
      duplex: true,
      rx_bytes: true,
      tx_bytes: true,
      rx_packets: true,
      tx_packets: true,
      rx_errors: true,
      tx_errors: true,
    },
  },
  /** DHCP servers. Reserved addresses and custom options are not read (MACs, free text). */
  dhcpServers: {
    path: 'cmdb/system.dhcp/server',
    results: 'list',
    maxItems: 200,
    fields: {
      id: true,
      status: true,
      interface: true,
      'lease-time': true,
      'default-gateway': true,
      netmask: true,
      'dns-service': true,
      'dns-server1': true,
      'dns-server2': true,
      'dns-server3': true,
      'dns-server4': true,
      domain: true,
      'ip-range': { id: true, 'start-ip': true, 'end-ip': true },
    },
  },
  /** DHCP leases, only to count them per interface (no MACs or host names are kept). */
  dhcpLeases: {
    path: 'monitor/system/dhcp',
    results: 'list',
    maxItems: 20_000,
    fields: { interface: true, status: true, type: true },
  },
  /** The live IPv4 routing table. */
  routesLive: {
    path: 'monitor/router/ipv4',
    results: 'list',
    maxItems: 5_000,
    fields: {
      ip_mask: true,
      gateway: true,
      interface: true,
      type: true,
      distance: true,
      metric: true,
      priority: true,
      is_tunnel_route: true,
      install_date: true,
    },
  },
  /** Configured static routes (when the live table cannot be read). */
  routesStatic: {
    path: 'cmdb/router/static',
    results: 'list',
    maxItems: 1_000,
    fields: { 'seq-num': true, status: true, dst: true, gateway: true, device: true, distance: true, priority: true, blackhole: true, comment: true },
  },
  /** Virtual IPs (port forwards / static NAT). */
  vips: {
    path: 'cmdb/firewall/vip',
    results: 'list',
    maxItems: 1_000,
    fields: {
      name: true,
      type: true,
      status: true,
      extip: true,
      extintf: true,
      extport: true,
      mappedport: true,
      portforward: true,
      protocol: true,
      comment: true,
      mappedip: { range: true },
    },
  },
  /** Live IPsec tunnels with their phase 2 selectors. */
  ipsecLive: {
    path: 'monitor/vpn/ipsec',
    results: 'list',
    maxItems: 500,
    fields: {
      name: true,
      comments: true,
      rgwy: true,
      type: true,
      connection_count: true,
      creation_time: true,
      incoming_bytes: true,
      outgoing_bytes: true,
      proxyid: {
        p2name: true,
        status: true,
        expire: true,
        proxysrc: { subnet: true },
        proxydst: { subnet: true },
      },
    },
  },
  /** IPsec phase 1 interfaces. No pre-shared keys, certificates or EAP/XAUTH credentials. */
  ipsecPhase1: {
    path: 'cmdb/vpn.ipsec/phase1-interface',
    results: 'list',
    maxItems: 500,
    fields: {
      name: true,
      type: true,
      interface: true,
      'ike-version': true,
      'remote-gw': true,
      'remotegw-ddns': true,
      'net-device': true,
      'add-route': true,
      comments: true,
    },
  },
  /** IPsec phase 2 selectors. */
  ipsecPhase2: {
    path: 'cmdb/vpn.ipsec/phase2-interface',
    results: 'list',
    maxItems: 2_000,
    fields: {
      name: true,
      phase1name: true,
      'src-addr-type': true,
      'src-subnet': true,
      'src-start-ip': true,
      'src-end-ip': true,
      'src-name': true,
      'dst-addr-type': true,
      'dst-subnet': true,
      'dst-start-ip': true,
      'dst-end-ip': true,
      'dst-name': true,
      'auto-negotiate': true,
      comments: true,
    },
  },
  /** Firewall address objects. */
  addresses: {
    path: 'cmdb/firewall/address',
    results: 'list',
    maxItems: 5_000,
    fields: {
      name: true,
      type: true,
      subnet: true,
      'start-ip': true,
      'end-ip': true,
      fqdn: true,
      'associated-interface': true,
      comment: true,
    },
  },
} as const satisfies Record<string, FortiosEndpoint>;

export type FortiosEndpointName = keyof typeof FORTIOS_ENDPOINTS;

/** Field names that must never be on an allowlist (checked by a test, as a second line behind the allowlists). */
export const SECRET_NAME = /pass|psk|secret|key|cert|token|priv|cred|auth|eap|ppk|sign/i;

function scalar(v: unknown): string | number | boolean | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.length > MAX_STRING ? `${v.slice(0, MAX_STRING)}...` : v;
  return undefined;
}

/** A copy of `value` with only the allowlisted fields (see Shape). */
export function pick(value: unknown, shape: Shape, depth = 0): Raw | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value) || depth > 4) return undefined;
  const src = value as Raw;
  const out: Raw = {};
  for (const [field, rule] of Object.entries(shape)) {
    if (!Object.prototype.hasOwnProperty.call(src, field)) continue;
    const v = src[field];
    if (rule === true) {
      const s = scalar(v);
      if (s !== undefined) out[field] = s;
    } else if (Array.isArray(v)) {
      out[field] = v
        .slice(0, 200)
        .map((x) => pick(x, rule, depth + 1))
        .filter((x): x is Raw => x !== undefined);
    } else {
      const o = pick(v, rule, depth + 1);
      if (o !== undefined) out[field] = o;
    }
  }
  return out;
}

/** What the proxy helper returns: allowlisted rows, plus the FortiOS version and VDOM from the envelope. */
export interface FortiosResult {
  rows: Raw[];
  /** More rows than the endpoint's maxItems were returned; the rest were dropped. */
  truncated?: boolean;
  version?: string;
  build?: number;
  vdom?: string;
}

/**
 * The allowlisted rows of a FortiOS answer. `results` is a list, or (for
 * monitor system/interface) an object keyed by interface name, whose key
 * becomes `name` when the value has none. The envelope's own fields are kept
 * only where named (version, build, vdom).
 */
export function filterFortios(body: unknown, endpoint: FortiosEndpoint): FortiosResult {
  const env = (body && typeof body === 'object' && !Array.isArray(body) ? body : {}) as Raw;
  const results = env.results;
  let items: Raw[] = [];
  if (Array.isArray(results)) {
    items = results.filter((x): x is Raw => !!x && typeof x === 'object' && !Array.isArray(x));
  } else if (results && typeof results === 'object') {
    items = Object.entries(results as Raw)
      .filter(([, v]) => !!v && typeof v === 'object' && !Array.isArray(v))
      .map(([k, v]) => ((v as Raw).name === undefined ? { ...(v as Raw), name: k } : (v as Raw)));
  }
  const rows = items
    .slice(0, endpoint.maxItems)
    .map((x) => pick(x, endpoint.fields))
    .filter((x): x is Raw => x !== undefined);
  const version = typeof env.version === 'string' ? env.version.slice(0, 40) : undefined;
  const build = typeof env.build === 'number' ? env.build : undefined;
  const vdom = typeof env.vdom === 'string' ? env.vdom.slice(0, 40) : undefined;
  return {
    rows,
    ...(items.length > endpoint.maxItems ? { truncated: true } : {}),
    ...(version ? { version } : {}),
    ...(build !== undefined ? { build } : {}),
    ...(vdom ? { vdom } : {}),
  };
}
