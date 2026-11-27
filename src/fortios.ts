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
 * boolean); `'list'` keeps a list of scalars; a nested Shape keeps an object,
 * or each object in a list, with its own allowlist. A scalar where a list or
 * a nested Shape is expected is kept as that scalar (FortiOS versions differ:
 * an SD-WAN rule's health check is a name in 6.2 and a list in 7.x). Anything
 * else (other keys, objects where a scalar is expected) is dropped.
 */
export interface Shape {
  [field: string]: true | 'list' | Shape;
}

export interface FortiosEndpoint {
  /** Path under /api/v2/. */
  path: string;
  /**
   * How `results` comes back: a list of objects, or an object keyed by name
   * (monitor system/interface); `object` is one settings object (cmdb
   * system/sdwan), and `nested` an object keyed by name whose values are
   * keyed by interface (monitor system/link-monitor, virtual-wan/health-check),
   * flattened to one row per name and interface.
   */
  results: 'list' | 'map' | 'object' | 'nested';
  /** Fixed query parameters (never caller-supplied). */
  query?: Record<string, string>;
  fields: Shape;
  /** Most entries kept from `results`. */
  maxItems: number;
}

/** Longest string kept from any field. */
const MAX_STRING = 300;

/**
 * SD-WAN settings, the same in `system sdwan` (6.4+) and `system
 * virtual-wan-link` (6.2 and older; no zones there). Health checks can hold a
 * TWAMP password; it is not on the list.
 */
const SDWAN_FIELDS = {
  status: true,
  'load-balance-mode': true,
  zone: { name: true },
  members: {
    'seq-num': true,
    interface: true,
    zone: true,
    gateway: true,
    priority: true,
    cost: true,
    weight: true,
    status: true,
    comment: true,
  },
  'health-check': {
    name: true,
    server: true,
    protocol: true,
    port: true,
    'detect-mode': true,
    interval: true,
    failtime: true,
    recoverytime: true,
    members: { 'seq-num': true },
    sla: { id: true, 'latency-threshold': true, 'jitter-threshold': true, 'packetloss-threshold': true },
    'update-static-route': true,
    'update-cascade-interface': true,
  },
  service: {
    id: true,
    name: true,
    status: true,
    mode: true,
    'input-device': { name: true },
    src: { name: true },
    dst: { name: true },
    'priority-members': { 'seq-num': true },
    'priority-zone': { name: true },
    'health-check': { name: true },
    sla: { 'health-check': true, id: true },
  },
} as const satisfies Shape;

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
      vrf: true,
      install_date: true,
    },
  },
  /** Configured static routes, every routing field (forticloud_get_routing). */
  staticRoutes: {
    path: 'cmdb/router/static',
    results: 'list',
    maxItems: 1_000,
    fields: {
      'seq-num': true,
      status: true,
      dst: true,
      dstaddr: true,
      gateway: true,
      device: true,
      distance: true,
      priority: true,
      weight: true,
      blackhole: true,
      'dynamic-gateway': true,
      /** 7.0+: the SD-WAN zones the route uses. */
      'sdwan-zone': { name: true },
      /** 6.4: the route uses SD-WAN. */
      sdwan: true,
      /** 6.2 and older: the route uses SD-WAN. */
      'virtual-wan-link': true,
      'link-monitor-exempt': true,
      vrf: true,
      comment: true,
    },
  },
  /** Policy routes, briefly. */
  policyRoutes: {
    path: 'cmdb/router/policy',
    results: 'list',
    maxItems: 1_000,
    fields: {
      'seq-num': true,
      status: true,
      action: true,
      'input-device': { name: true },
      src: { subnet: true },
      srcaddr: { name: true },
      dst: { subnet: true },
      dstaddr: { name: true },
      protocol: true,
      'start-port': true,
      'end-port': true,
      gateway: true,
      'output-device': true,
      comments: true,
    },
  },
  /** Link monitors (the health checks that can remove static routes). */
  linkMonitorConfig: {
    path: 'cmdb/system/link-monitor',
    results: 'list',
    maxItems: 200,
    fields: {
      name: true,
      status: true,
      'addr-mode': true,
      srcintf: true,
      server: { address: true },
      protocol: true,
      port: true,
      'gateway-ip': true,
      route: { subnet: true },
      interval: true,
      'probe-timeout': true,
      failtime: true,
      recoverytime: true,
      'update-static-route': true,
      'update-cascade-interface': true,
      'update-policy-route': true,
    },
  },
  /** Live link-monitor state, per monitor and interface. */
  linkMonitorLive: {
    path: 'monitor/system/link-monitor',
    results: 'nested',
    maxItems: 500,
    fields: {
      name: true,
      interface: true,
      status: true,
      latency: true,
      jitter: true,
      packet_loss: true,
      packet_sent: true,
      packet_received: true,
      state_changed: true,
    },
  },
  /** SD-WAN settings (FortiOS 6.4 and later). */
  sdwanConfig: {
    path: 'cmdb/system/sdwan',
    results: 'object',
    maxItems: 1,
    fields: SDWAN_FIELDS,
  },
  /** SD-WAN settings on FortiOS 6.2 and older, where they are `system virtual-wan-link`. */
  sdwanLegacy: {
    path: 'cmdb/system/virtual-wan-link',
    results: 'object',
    maxItems: 1,
    fields: SDWAN_FIELDS,
  },
  /** Live SD-WAN health-check state, per health check and member. */
  sdwanHealthLive: {
    path: 'monitor/virtual-wan/health-check',
    results: 'nested',
    maxItems: 500,
    fields: {
      name: true,
      interface: true,
      status: true,
      latency: true,
      jitter: true,
      packet_loss: true,
      packet_sent: true,
      packet_received: true,
      sla_targets_met: 'list',
      state_changed: true,
    },
  },
  /** Live SD-WAN member state (FortiOS 6.4 and later). */
  sdwanMembersLive: {
    path: 'monitor/virtual-wan/members',
    results: 'map',
    maxItems: 200,
    fields: {
      name: true,
      interface: true,
      link: true,
      status: true,
      session: true,
      tx_bandwidth: true,
      rx_bandwidth: true,
      state_changed: true,
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
  /**
   * IPsec phase 1 interfaces with their failover settings (forticloud_get_vpn): backup-of
   * (`monitor`, a name on 6.4, a list on 7.x) and its hold-down, DPD, idle timeout, auto-negotiate,
   * route and ADVPN switches. Never the pre-shared key (`psksecret`, `psksecret-remote`), the
   * ADVPN key (`auto-discovery-psk`), certificates, peer IDs, XAUTH/EAP users or PPKs.
   */
  vpnPhase1: {
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
      'local-gw': true,
      'mode-cfg': true,
      monitor: { name: true },
      'monitor-min': true,
      'monitor-hold-down-type': true,
      'monitor-hold-down-delay': true,
      'monitor-hold-down-time': true,
      'monitor-hold-down-weekday': true,
      dpd: true,
      'dpd-retrycount': true,
      'dpd-retryinterval': true,
      'idle-timeout': true,
      'idle-timeoutinterval': true,
      'auto-negotiate': true,
      keepalive: true,
      'net-device': true,
      'add-route': true,
      distance: true,
      priority: true,
      'exchange-interface-ip': true,
      'auto-discovery-sender': true,
      'auto-discovery-receiver': true,
      'auto-discovery-forwarder': true,
      'auto-discovery-shortcuts': true,
      comments: true,
    },
  },
  /** IPsec phase 2 selectors with auto-negotiate and keepalive (forticloud_get_vpn). */
  vpnPhase2: {
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
      keepalive: true,
      comments: true,
    },
  },
  /**
   * Live IPsec tunnels with byte counters per tunnel and per phase 2 (forticloud_get_vpn). The
   * selectors are `proxy_src`/`proxy_dst` in the FortiOS reference and `proxysrc`/`proxydst` in
   * some answers; both are kept. No dial-up user names.
   */
  vpnIpsecLive: {
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
        incoming_bytes: true,
        outgoing_bytes: true,
        proxy_src: { subnet: true },
        proxy_dst: { subnet: true },
        proxysrc: { subnet: true },
        proxydst: { subnet: true },
      },
    },
  },
  /** BGP settings, briefly: the AS, router ID, neighbors, neighbor groups and ranges. No neighbor passwords. */
  bgpConfig: {
    path: 'cmdb/router/bgp',
    results: 'object',
    maxItems: 1,
    fields: {
      as: true,
      'router-id': true,
      neighbor: { ip: true, 'remote-as': true, interface: true, 'update-source': true, description: true, shutdown: true, bfd: true },
      'neighbor-group': { name: true, 'remote-as': true, interface: true, 'update-source': true },
      'neighbor-range': { id: true, prefix: true, 'neighbor-group': true },
    },
  },
  /**
   * Live BGP neighbors. The FortiOS reference documents the address, local address, remote AS,
   * admin status, state and type; an uptime or prefix count is kept when a version adds one.
   */
  bgpLive: {
    path: 'monitor/router/bgp/neighbors',
    results: 'list',
    maxItems: 1_000,
    fields: {
      neighbor_ip: true,
      local_ip: true,
      remote_as: true,
      admin_status: true,
      state: true,
      type: true,
      uptime: true,
      up_time: true,
      prefixes_received: true,
      received_prefixes: true,
    },
  },
  /** SSL-VPN settings, briefly: on or off, port, listening interfaces. No server certificate. */
  sslVpnConfig: {
    path: 'cmdb/vpn.ssl/settings',
    results: 'object',
    maxItems: 1,
    fields: { status: true, port: true, 'source-interface': { name: true } },
  },
  /** Live SSL-VPN sessions, only to count them: no user names, addresses or times are kept. */
  sslVpnLive: {
    path: 'monitor/vpn/ssl',
    results: 'list',
    maxItems: 5_000,
    fields: { index: true },
  },
  /**
   * Management access settings from `system global` (forticloud_get_admin_access): the admin
   * ports, telnet, HTTP to HTTPS redirect, idle timeout, lockout and the maintainer account.
   * Nothing else from `system global` is kept.
   */
  adminGlobal: {
    path: 'cmdb/system/global',
    results: 'object',
    maxItems: 1,
    fields: {
      'admin-sport': true,
      'admin-port': true,
      'admin-ssh-port': true,
      'admin-telnet': true,
      'admin-telnet-port': true,
      'admin-https-redirect': true,
      admintimeout: true,
      'admin-lockout-threshold': true,
      'admin-lockout-duration': true,
      'admin-maintainer': true,
    },
  },
  /** Interfaces with what they allow to the FortiGate itself (allowaccess), IPv4 secondary and IPv6 included. */
  adminInterfaces: {
    path: 'cmdb/system/interface',
    results: 'list',
    maxItems: 500,
    fields: {
      name: true,
      vdom: true,
      type: true,
      role: true,
      mode: true,
      ip: true,
      status: true,
      alias: true,
      allowaccess: true,
      'dedicated-to': true,
      secondaryip: { id: true, ip: true, allowaccess: true },
      ipv6: { 'ip6-mode': true, 'ip6-address': true, 'ip6-allowaccess': true },
    },
  },
  /**
   * Administrators: profile, VDOMs, trusted hosts, two-factor, wildcard and remote group. Never the
   * password or its hash, SSH public keys, the FortiToken serial or any other credential field.
   */
  admins: {
    path: 'cmdb/system/admin',
    results: 'list',
    maxItems: 500,
    fields: {
      name: true,
      accprofile: true,
      vdom: { name: true },
      trusthost1: true,
      trusthost2: true,
      trusthost3: true,
      trusthost4: true,
      trusthost5: true,
      trusthost6: true,
      trusthost7: true,
      trusthost8: true,
      trusthost9: true,
      trusthost10: true,
      'ip6-trusthost1': true,
      'ip6-trusthost2': true,
      'ip6-trusthost3': true,
      'ip6-trusthost4': true,
      'ip6-trusthost5': true,
      'ip6-trusthost6': true,
      'ip6-trusthost7': true,
      'ip6-trusthost8': true,
      'ip6-trusthost9': true,
      'ip6-trusthost10': true,
      'two-factor': true,
      wildcard: true,
      'remote-group': true,
    },
  },
  /** REST API administrators: profile and trusted hosts. Never the API key. */
  apiUsers: {
    path: 'cmdb/system/api-user',
    results: 'list',
    maxItems: 200,
    fields: {
      name: true,
      accprofile: true,
      vdom: { name: true },
      trusthost: { id: true, type: true, 'ipv4-trustip': true, 'ipv6-trustip': true },
    },
  },
  /** Local-in policies (traffic to the FortiGate itself). */
  localIn: {
    path: 'cmdb/firewall/local-in-policy',
    results: 'list',
    maxItems: 1_000,
    fields: {
      policyid: true,
      intf: { name: true },
      srcaddr: { name: true },
      'srcaddr-negate': true,
      dstaddr: { name: true },
      'dstaddr-negate': true,
      service: { name: true },
      'service-negate': true,
      action: true,
      schedule: true,
      status: true,
      comments: true,
    },
  },
  /**
   * SNMP v1/v2c communities: which hosts may poll or get traps, and what is on. Never `name`:
   * the community name is the community string (the shared secret).
   */
  snmpCommunities: {
    path: 'cmdb/system.snmp/community',
    results: 'list',
    maxItems: 100,
    fields: {
      id: true,
      status: true,
      'query-v1-status': true,
      'query-v2c-status': true,
      'trap-v1-status': true,
      'trap-v2c-status': true,
      hosts: { id: true, ip: true, interface: true, 'host-type': true },
      hosts6: { id: true, ipv6: true, interface: true, 'host-type': true },
    },
  },
  /** SNMP v3 users: name, security level, queries and trap hosts. Never the authentication or privacy password or protocol. */
  snmpUsers: {
    path: 'cmdb/system.snmp/user',
    results: 'list',
    maxItems: 100,
    fields: {
      name: true,
      status: true,
      'security-level': true,
      queries: true,
      'query-port': true,
      'trap-status': true,
      'notify-hosts': true,
      'notify-hosts6': true,
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

/** Most entries kept from a nested list (secondary IPs, DHCP ranges, phase 2 selectors...). */
export const MAX_NESTED = 200;

/**
 * A copy of `value` with only the allowlisted fields (see Shape). A nested
 * list longer than MAX_NESTED is cut, and `state.cut` is set so the caller
 * can say so.
 */
export function pick(value: unknown, shape: Shape, depth = 0, state?: { cut: boolean }): Raw | undefined {
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
      if (v.length > MAX_NESTED && state) state.cut = true;
      const kept = v.slice(0, MAX_NESTED);
      out[field] =
        rule === 'list'
          ? kept.map(scalar).filter((x) => x !== undefined)
          : kept.map((x) => pick(x, rule, depth + 1, state)).filter((x): x is Raw => x !== undefined);
    } else if (v && typeof v === 'object') {
      if (rule === 'list') continue;
      const o = pick(v, rule, depth + 1, state);
      if (o !== undefined) out[field] = o;
    } else {
      // A plain value where this FortiOS version has no list or object.
      const s = scalar(v);
      if (s !== undefined) out[field] = s;
    }
  }
  return out;
}

/** What the proxy helper returns: allowlisted rows, plus the FortiOS version and VDOM from the envelope. */
export interface FortiosResult {
  rows: Raw[];
  /** More rows than the endpoint's maxItems were returned; the rest were dropped. */
  truncated?: boolean;
  /** With truncated: how many rows the device returned. */
  returned?: number;
  /** A nested list in some row was longer than MAX_NESTED and was cut. */
  nestedCut?: boolean;
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
  const isObj = (v: unknown): v is Raw => !!v && typeof v === 'object' && !Array.isArray(v);
  if (endpoint.results === 'object' && isObj(results)) {
    items = [results];
  } else if (endpoint.results === 'nested' && isObj(results)) {
    // {name: {interface: {status...}}}: one row per name and interface. A
    // value with no objects inside is already one row.
    for (const [name, v] of Object.entries(results)) {
      if (!isObj(v)) continue;
      const inner = Object.entries(v).filter(([, x]) => isObj(x)) as [string, Raw][];
      if (inner.length === 0) items.push({ ...v, name });
      else for (const [iface, x] of inner) items.push({ ...x, name, interface: typeof x.interface === 'string' ? x.interface : iface });
    }
  } else if (Array.isArray(results)) {
    items = results.filter((x): x is Raw => !!x && typeof x === 'object' && !Array.isArray(x));
  } else if (results && typeof results === 'object') {
    items = Object.entries(results as Raw)
      .filter(([, v]) => !!v && typeof v === 'object' && !Array.isArray(v))
      .map(([k, v]) => ((v as Raw).name === undefined ? { ...(v as Raw), name: k } : (v as Raw)));
  }
  const state = { cut: false };
  const rows = items
    .slice(0, endpoint.maxItems)
    .map((x) => pick(x, endpoint.fields, 0, state))
    .filter((x): x is Raw => x !== undefined);
  const version = typeof env.version === 'string' ? env.version.slice(0, 40) : undefined;
  const build = typeof env.build === 'number' ? env.build : undefined;
  const vdom = typeof env.vdom === 'string' ? env.vdom.slice(0, 40) : undefined;
  return {
    rows,
    ...(items.length > endpoint.maxItems ? { truncated: true, returned: items.length } : {}),
    ...(state.cut ? { nestedCut: true } : {}),
    ...(version ? { version } : {}),
    ...(build !== undefined ? { build } : {}),
    ...(vdom ? { vdom } : {}),
  };
}
