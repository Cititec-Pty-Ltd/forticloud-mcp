/** IPv4 helpers for the network tools. Addresses are unsigned 32-bit numbers. */

export interface Net {
  /** The address as written (may have host bits set, e.g. an interface address). */
  ip: number;
  prefix: number;
}

/** "a.b.c.d" as a number; undefined unless four decimal octets 0-255. */
export function parseIpv4(s: unknown): number | undefined {
  if (typeof s !== 'string') return undefined;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return undefined;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return undefined;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function formatIpv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** "255.255.255.0" as 24; undefined when the mask is not contiguous. */
export function prefixOfMask(s: unknown): number | undefined {
  const n = parseIpv4(s);
  if (n === undefined) return undefined;
  for (let p = 0; p <= 32; p++) if (maskOf(p) === n) return p;
  return undefined;
}

export const networkOf = (net: Net): number => (net.ip & maskOf(net.prefix)) >>> 0;

/** "10.0.0.1/24" (the address as given, with its prefix). */
export const cidr = (net: Net): string => `${formatIpv4(net.ip)}/${net.prefix}`;

/** "10.0.0.0/24" (the network). */
export const networkCidr = (net: Net): string => `${formatIpv4(networkOf(net))}/${net.prefix}`;

/**
 * A FortiOS address with its mask in any form FortiOS writes: "a.b.c.d m.m.m.m"
 * (cmdb), "a.b.c.d/nn", or an address plus a separate prefix length (monitor).
 * undefined for 0.0.0.0 (no address) and anything unreadable.
 */
export function parseFortiosNet(value: unknown, prefixLength?: unknown): Net | undefined {
  if (typeof value !== 'string') return undefined;
  const s = value.trim();
  let ip: number | undefined;
  let prefix: number | undefined;
  const parts = s.split(/[\s/]+/);
  if (parts.length === 2) {
    ip = parseIpv4(parts[0]);
    prefix = /^\d{1,2}$/.test(parts[1]) ? Number(parts[1]) : prefixOfMask(parts[1]);
  } else if (parts.length === 1) {
    ip = parseIpv4(parts[0]);
    const p = typeof prefixLength === 'string' && /^\d{1,2}$/.test(prefixLength.trim()) ? Number(prefixLength) : prefixLength;
    prefix = typeof p === 'number' && Number.isInteger(p) ? p : typeof p === 'string' ? prefixOfMask(p) : undefined;
  }
  if (ip === undefined || prefix === undefined || prefix < 0 || prefix > 32 || ip === 0) return undefined;
  return { ip, prefix };
}

/** A FortiOS subnet ("a.b.c.d m.m.m.m", "a.b.c.d/nn") as "network/prefix"; the text as is when it is not one. */
export function subnetText(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const parts = value.trim().split(/[\s/]+/);
  if (parts.length === 2) {
    const ip = parseIpv4(parts[0]);
    const prefix = /^\d{1,2}$/.test(parts[1]) ? Number(parts[1]) : prefixOfMask(parts[1]);
    if (ip !== undefined && prefix !== undefined && prefix <= 32) return networkCidr({ ip, prefix });
  }
  return value.trim().slice(0, 100);
}

/**
 * Not a public address: RFC 1918, carrier-grade NAT (100.64.0.0/10),
 * loopback, link-local, "this network" (0/8), multicast and reserved (224/3).
 */
export function isPrivate(ip: number): boolean {
  const inNet = (base: string, prefix: number) => (ip & maskOf(prefix)) >>> 0 === parseIpv4(base);
  return (
    inNet('10.0.0.0', 8) ||
    inNet('172.16.0.0', 12) ||
    inNet('192.168.0.0', 16) ||
    inNet('100.64.0.0', 10) ||
    inNet('127.0.0.0', 8) ||
    inNet('169.254.0.0', 16) ||
    inNet('0.0.0.0', 8) ||
    inNet('224.0.0.0', 3)
  );
}

/** The caller's IP ("a.b.c.d") or subnet ("a.b.c.d/nn"); `host` when no prefix was given. */
export function parseQuery(s: string): (Net & { host: boolean }) | undefined {
  const m = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*(?:\/\s*(\d{1,2}))?\s*$/.exec(s);
  if (!m) return undefined;
  const ip = parseIpv4(m[1]);
  const prefix = m[2] === undefined ? 32 : Number(m[2]);
  if (ip === undefined || prefix > 32) return undefined;
  return { ip, prefix, host: m[2] === undefined };
}

export type Relation = 'interface address' | 'inside the interface subnet' | 'contains the interface subnet' | 'same subnet';

/**
 * How a query relates to an interface's network, or undefined when they do
 * not overlap. Two IPv4 networks overlap only when one contains the other.
 */
export function relate(query: Net & { host: boolean }, iface: Net): Relation | undefined {
  const q = networkOf(query);
  const n = networkOf(iface);
  if (query.host || query.prefix === 32) {
    if (query.ip === iface.ip) return 'interface address';
    return ((query.ip & maskOf(iface.prefix)) >>> 0) === n ? 'inside the interface subnet' : undefined;
  }
  if (query.prefix === iface.prefix) return q === n ? 'same subnet' : undefined;
  if (query.prefix > iface.prefix) return ((q & maskOf(iface.prefix)) >>> 0) === n ? 'inside the interface subnet' : undefined;
  return ((n & maskOf(query.prefix)) >>> 0) === q ? 'contains the interface subnet' : undefined;
}
