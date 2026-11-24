import { gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { decodeBody, setFetchForTests } from '../client.js';
import { FORTIOS_ENDPOINTS, SECRET_NAME, filterFortios } from '../fortios.js';
import type { Shape } from '../fortios.js';
import { clearCaches, timeIn } from '../tools/format.js';
import { dispatchToolCall } from '../tools/index.js';
import { cidr, isPrivate, parseFortiosNet, parseIpv4, parseQuery, relate, subnetText } from '../tools/ip.js';
import { FIND_IP_LIMITS, clearNetworkCaches } from '../tools/network.js';
import { FGT, dataOf, fakeForticloud, json, textOf } from './test-helpers.js';
import type { Call } from './test-helpers.js';

const SN = 'FGT60FTK00000001';
const SN2 = 'FGT40FTK00000002';
const SN3 = 'FGT60FTK00000003';
const DEVICES = [
  { sn: SN, name: 'client-a-fw', model: 'FortiGate 60F', firmwareVersion: '7.2.8', tunnelAlive: true, subAccountOid: 100 },
  { sn: SN2, name: 'client-b-fw', model: 'FortiGate 40F', firmwareVersion: '7.0.15', tunnelAlive: false, subAccountOid: 200 },
  { sn: SN3, name: 'client-c-fw', model: 'FortiGate 60F', firmwareVersion: '7.4.4', tunnelAlive: true, subAccountOid: 300 },
];
const SUBACCOUNTS = [
  { oid: 100, name: 'Example Client A' },
  { oid: 200, name: 'Example Client B' },
  { oid: 300, name: 'Example Client C' },
];

/** Secret values a FortiOS answer might carry; none may ever appear in a result. */
const SECRETS = {
  password: 'SECRET-pppoe-pass-1',
  'eap-password': 'SECRET-eap-pass-2',
  'eap-ca-cert': 'SECRET-eap-cert-3',
  'eap-user-cert': 'SECRET-eap-cert-4',
  psksecret: 'SECRET-psk-5',
  'psksecret-remote': 'SECRET-psk-6',
  'ppk-secret': 'SECRET-ppk-7',
  certificate: [{ name: 'SECRET-cert-8' }],
  'private-key': 'SECRET-key-9',
  token: 'SECRET-token-10',
  apikey: 'SECRET-apikey-11',
  'authpasswd': 'SECRET-xauth-12',
  'auth-password': 'SECRET-auth-13',
  'snmp-index': 7,
};
const SECRET_VALUES = ['SECRET-'];
const SECRET_KEYS = ['password', 'psk', 'ppk', 'private-key', 'certificate', 'token', 'apikey', 'authpasswd', 'eap-'];

const envelope = (results: unknown, extra: Record<string, unknown> = {}) => ({
  http_method: 'GET',
  results,
  vdom: 'root',
  path: 'x',
  name: 'y',
  status: 'success',
  http_status: 200,
  serial: SN,
  version: 'v7.4.4',
  build: 2662,
  ...extra,
});

const IF_CONFIG = [
  { name: 'wan1', type: 'physical', role: 'wan', mode: 'dhcp', ip: '0.0.0.0 0.0.0.0', status: 'up', allowaccess: 'ping', description: 'Fibre', ...SECRETS },
  { name: 'wan2', type: 'physical', role: 'wan', mode: 'pppoe', ip: '0.0.0.0 0.0.0.0', username: 'user@isp.example', password: 'SECRET-pppoe-pass-x' },
  {
    name: 'internal',
    type: 'hard-switch',
    role: 'lan',
    mode: 'static',
    ip: '192.168.10.1 255.255.255.0',
    alias: 'LAN',
    secondaryip: [{ id: 1, ip: '10.99.0.1 255.255.255.0', allowaccess: 'ping', secret: 'SECRET-nested' }],
    member: [{ 'interface-name': 'port1' }, { 'interface-name': 'port2' }],
  },
  { name: 'vlan20', type: 'vlan', vlanid: 20, interface: 'internal', role: 'lan', mode: 'static', ip: '10.20.0.1 255.255.255.0', description: 'Voice' },
  { name: 'dmz', type: 'physical', role: 'dmz', mode: 'static', ip: '203.0.113.1 255.255.255.248' },
  { name: 'ssl.root', type: 'tunnel', ip: '0.0.0.0 0.0.0.0' },
];
const IF_LIVE = {
  wan1: { id: 'wan1', name: 'wan1', mac: '00:00:5e:00:53:01', ip: '198.51.100.20', mask: 30, link: true, speed: 1000, duplex: 1, tx_bytes: 5, key: 'SECRET-live-key' },
  internal: { id: 'internal', name: 'internal', mac: '00:00:5e:00:53:02', ip: '192.168.10.1', mask: 24, link: true, speed: 1000 },
  vlan20: { name: 'vlan20', ip: '10.20.0.1', mask: 24, link: true },
  dmz: { name: 'dmz', ip: '203.0.113.1', mask: 29, link: false, speed: 0 },
};

const FOS = (sn: string, path: string) => `${FGT}/fgt/${sn}/api/v2/${path}`;

function networkRoutes(sn = SN, extra: Record<string, any> = {}) {
  return {
    [`${FGT}/devices`]: json(DEVICES),
    [`${FGT}/subaccounts`]: json(SUBACCOUNTS),
    [FOS(sn, 'cmdb/system/interface')]: json(envelope(IF_CONFIG)),
    [FOS(sn, 'monitor/system/interface')]: json(envelope(IF_LIVE)),
    [FOS(sn, 'cmdb/system.dhcp/server')]: json(
      envelope([
        {
          id: 1,
          status: 'enable',
          interface: 'internal',
          'lease-time': 604800,
          'default-gateway': '192.168.10.1',
          netmask: '255.255.255.0',
          'dns-service': 'specify',
          'dns-server1': '192.168.10.1',
          'dns-server2': '0.0.0.0',
          'ip-range': [{ id: 1, 'start-ip': '192.168.10.100', 'end-ip': '192.168.10.199' }],
          'reserved-address': [{ ip: '192.168.10.50', mac: '00:00:5e:00:53:99', description: 'printer' }],
          options: [{ code: 43, value: 'SECRET-option' }],
          'vci-string': 'x',
        },
      ])
    ),
    [FOS(sn, 'monitor/system/dhcp')]: json(
      envelope([
        { ip: '192.168.10.101', mac: '00:00:5e:00:53:10', hostname: 'laptop-1', interface: 'internal', status: 'leased' },
        { ip: '192.168.10.102', mac: '00:00:5e:00:53:11', hostname: 'laptop-2', interface: 'internal', status: 'leased' },
      ])
    ),
    [FOS(sn, 'monitor/router/ipv4')]: json(
      envelope([
        { ip_version: 4, type: 'connect', ip_mask: '192.168.10.0/24', distance: 0, metric: 0, gateway: '0.0.0.0', interface: 'internal' },
        { ip_version: 4, type: 'static', ip_mask: '0.0.0.0/0', distance: 5, metric: 0, priority: 1, gateway: '198.51.100.21', interface: 'wan1' },
      ])
    ),
    [FOS(sn, 'cmdb/firewall/vip')]: json(
      envelope([
        { name: 'web-in', type: 'static-nat', extip: '198.51.100.20', extintf: 'wan1', portforward: 'enable', protocol: 'tcp', extport: '443', mappedport: '443', mappedip: [{ range: '192.168.10.20' }], comment: 'Web' },
      ])
    ),
    [FOS(sn, 'monitor/vpn/ipsec')]: json(
      envelope([
        {
          name: 'to-branch',
          rgwy: '192.0.2.50',
          type: 'automatic',
          proxyid: [{ p2name: 'to-branch', status: 'up', proxysrc: [{ subnet: '192.168.10.0/255.255.255.0' }], proxydst: [{ subnet: '10.30.0.0/255.255.0.0' }] }],
        },
      ])
    ),
    [FOS(sn, 'cmdb/vpn.ipsec/phase1-interface')]: json(
      envelope([
        { name: 'to-branch', type: 'static', interface: 'wan1', 'ike-version': '2', 'remote-gw': '192.0.2.50', ...SECRETS },
        { name: 'old-site', type: 'static', interface: 'wan1', 'remote-gw': '192.0.2.60', psksecret: 'SECRET-psk-old' },
      ])
    ),
    [FOS(sn, 'cmdb/vpn.ipsec/phase2-interface')]: json(
      envelope([
        { name: 'old-site', phase1name: 'old-site', 'src-addr-type': 'subnet', 'src-subnet': '192.168.10.0 255.255.255.0', 'dst-addr-type': 'subnet', 'dst-subnet': '10.40.0.0 255.255.0.0', keylife: 3600 },
      ])
    ),
    [FOS(sn, 'cmdb/firewall/address')]: json(
      envelope([
        { name: 'LAN', type: 'ipmask', subnet: '192.168.10.0 255.255.255.0' },
        { name: 'pool', type: 'iprange', 'start-ip': '10.0.0.5', 'end-ip': '10.0.0.9' },
        { name: 'site', type: 'fqdn', fqdn: 'www.example.com' },
      ])
    ),
    ...extra,
  };
}

const call = (name: string, args: Record<string, unknown> = {}) => dispatchToolCall(name, args);
const DEFAULT_LIMITS = { ...FIND_IP_LIMITS };

beforeEach(() => {
  process.env.FORTICLOUD_API_ID = 'APIUSER0000000000000';
  process.env.FORTICLOUD_API_PASSWORD = 'Sup3r-Secret-Passw0rd!';
  for (const k of ['FORTICLOUD_AUTH_URL', 'FORTICLOUD_ASSET_URL', 'FORTICLOUD_FGT_URL', 'FORTICLOUD_UNTRUSTED_MARKERS', 'FORTICLOUD_TIME_ZONE']) delete process.env[k];
  clearCaches();
  clearNetworkCaches();
  Object.assign(FIND_IP_LIMITS, DEFAULT_LIMITS);
});
afterEach(() => setFetchForTests(undefined));

const fortiosCalls = (calls: Call[]) => calls.filter((c) => c.url.pathname.includes('/fgt/'));

describe('FortiOS proxy allowlists', () => {
  it('no allowlisted field name looks like a secret', () => {
    const names: string[] = [];
    const walk = (shape: Shape) => {
      for (const [k, v] of Object.entries(shape)) {
        names.push(k);
        if (v !== true) walk(v);
      }
    };
    for (const e of Object.values(FORTIOS_ENDPOINTS)) walk(e.fields);
    expect(names.length).toBeGreaterThan(50);
    expect(names.filter((n) => SECRET_NAME.test(n))).toEqual([]);
  });

  it('filterFortios keeps only allowlisted fields, nested ones too, from a list or a map', () => {
    const list = filterFortios(envelope(IF_CONFIG), FORTIOS_ENDPOINTS.interfaceConfig);
    const text = JSON.stringify(list);
    for (const v of SECRET_VALUES) expect(text).not.toContain(v);
    for (const k of SECRET_KEYS) expect(text).not.toContain(`"${k}`);
    expect(text).not.toContain('username');
    expect(list.rows[2].secondaryip).toEqual([{ id: 1, ip: '10.99.0.1 255.255.255.0' }]);
    expect(list).toMatchObject({ version: 'v7.4.4', build: 2662, vdom: 'root' });
    expect(list).not.toHaveProperty('serial');
    const map = filterFortios(envelope(IF_LIVE), FORTIOS_ENDPOINTS.interfaceLive);
    expect(map.rows.map((r) => r.name)).toEqual(['wan1', 'internal', 'vlan20', 'dmz']);
    expect(JSON.stringify(map)).not.toContain('SECRET');
    // An object where a scalar is allowed is dropped, not copied.
    const odd = filterFortios(envelope([{ name: { password: 'SECRET-x' }, ip: ['SECRET-y'] }]), FORTIOS_ENDPOINTS.interfaceConfig);
    expect(odd.rows).toEqual([{}]);
  });

  it('get_network never returns a secret field or value, in any section', async () => {
    const { fn } = fakeForticloud(networkRoutes());
    setFetchForTests(fn);
    const res = await call('forticloud_get_network', { serial: SN, sections: ['interfaces', 'dhcp', 'routes', 'vips', 'vpn', 'addresses'], all_interfaces: true });
    expect(res.isError).toBeFalsy();
    const text = textOf(res);
    for (const v of SECRET_VALUES) expect(text).not.toContain(v);
    for (const k of ['psk', 'ppk', 'private-key', 'certificate', 'token', 'apikey', 'authpasswd', 'eap-', 'password', 'hostname', 'laptop-1', '00:00:5e:00:53:10', 'printer', 'keylife']) {
      expect(text).not.toContain(k);
    }
  });

  it('only GETs the fixed FortiOS paths, and passes a VDOM; a bad VDOM is refused before any request', async () => {
    const { fn, calls } = fakeForticloud(networkRoutes());
    setFetchForTests(fn);
    await call('forticloud_get_network', { serial: SN, sections: ['interfaces', 'dhcp', 'routes', 'vips', 'vpn', 'addresses'], vdom: 'customer1' });
    const fos = fortiosCalls(calls);
    expect(fos.every((c) => c.method === 'GET')).toBe(true);
    const allowed = new Set(Object.values(FORTIOS_ENDPOINTS).map((e) => `/forticloudapi/v1/fgt/${SN}/api/v2/${e.path}`));
    expect(fos.every((c) => allowed.has(c.url.pathname))).toBe(true);
    expect(fos.every((c) => c.url.searchParams.get('vdom') === 'customer1')).toBe(true);
    expect(fos.every((c) => c.auth === 'Bearer tok-fortigatecloud')).toBe(true);
    const live = fos.find((c) => c.url.pathname.endsWith('monitor/system/interface'))!;
    expect(live.url.searchParams.get('include_vlan')).toBe('true');

    const before = calls.length;
    const bad = await call('forticloud_get_network', { serial: SN, vdom: 'root/../x' });
    expect(bad.isError).toBe(true);
    expect(bad.structuredContent).toMatchObject({ error_type: 'invalid_input' });
    expect(calls.length).toBe(before);
    const badSerial = await call('forticloud_get_network', { serial: '../admin' });
    expect(badSerial.structuredContent).toMatchObject({ error_type: 'invalid_input' });
    expect(calls.length).toBe(before);
  });

  it('reads a gzipped answer, with or without Content-Encoding', async () => {
    const gz = (body: unknown, headers: Record<string, string>) => () =>
      new Response(gzipSync(Buffer.from(JSON.stringify(body))), { status: 200, headers: { 'Content-Type': 'application/json', ...headers } });
    const { fn } = fakeForticloud(
      networkRoutes(SN, {
        [FOS(SN, 'cmdb/system/interface')]: gz(envelope(IF_CONFIG), { 'Content-Encoding': 'gzip' }),
        [FOS(SN, 'monitor/system/interface')]: gz(envelope(IF_LIVE), {}),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['interfaces'] }));
    expect(out.interfaces.interfaces.find((i: any) => i.name === 'vlan20')).toMatchObject({ vlanId: 20, configured: '10.20.0.1/24', live: '10.20.0.1/24' });
    expect(JSON.stringify(out)).not.toContain('SECRET');
    expect(decodeBody(new TextEncoder().encode('{"a":1}'), 'x', 200)).toBe('{"a":1}');
    expect(() => decodeBody(new Uint8Array([0x1f, 0x8b, 1, 2, 3]), 'x', 200)).toThrow(/could not be unzipped/);
  });
});

describe('forticloud_get_network', () => {
  it('interfaces: configured and live merged, CIDR, VLAN and parent, WAN and public marked, no-address ones hidden', async () => {
    const { fn } = fakeForticloud(networkRoutes());
    setFetchForTests(fn);
    process.env.FORTICLOUD_TIME_ZONE = 'Australia/Melbourne';
    const res = await call('forticloud_get_network', { serial: SN, sections: ['interfaces'] });
    expect(textOf(res)).toMatch(/^<forticloud-data>/);
    const out = dataOf(res);
    expect(out.device).toMatchObject({ serial: SN, name: 'client-a-fw', account: 'Example Client A', fortigateCloudConnection: 'online' });
    expect(out.fortios).toEqual({ version: 'v7.4.4', build: 2662, vdom: 'root' });
    expect(out.readAt).toMatch(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d Australia\/Melbourne$/);
    const s = out.interfaces;
    expect(s.source).toEqual({ configured: 'cmdb system/interface', live: 'monitor system/interface' });
    expect(s.total).toBe(6);
    expect(s.hiddenWithoutAddress).toBe(1); // ssl.root; a WAN interface is shown even with no address (wan2, PPPoE down)
    expect(s.interfaces.find((i: any) => i.name === 'wan2')).toMatchObject({ role: 'wan', mode: 'pppoe', wan: true });
    const byName = Object.fromEntries(s.interfaces.map((i: any) => [i.name, i]));
    expect(byName.wan1).toMatchObject({ role: 'wan', mode: 'dhcp', live: '198.51.100.20/30', link: 'up', speed: 1000, wan: true, publicIp: true, mac: '00:00:5e:00:53:01' });
    expect(byName.wan1.configured).toBeUndefined();
    expect(byName.dmz).toMatchObject({ configured: '203.0.113.1/29', publicIp: true, link: 'down' });
    expect(byName.dmz.wan).toBeUndefined();
    expect(byName.internal).toMatchObject({ alias: 'LAN', type: 'hard-switch', configured: '192.168.10.1/24', secondary: ['10.99.0.1/24'], members: ['port1', 'port2'] });
    expect(byName.internal.publicIp).toBeUndefined();
    expect(byName.vlan20).toMatchObject({ vlanId: 20, parent: 'internal', description: 'Voice' });
    // WAN and public first.
    expect(s.interfaces.slice(0, 3).map((i: any) => i.name).sort()).toEqual(['dmz', 'wan1', 'wan2']);

    const all = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['interfaces'], all_interfaces: true }));
    expect(all.interfaces.interfaces).toHaveLength(6);
    expect(all.interfaces.hiddenWithoutAddress).toBeUndefined();
  });

  it('dhcp, routes, vips and vpn by default; addresses only when asked', async () => {
    const { fn, calls } = fakeForticloud(networkRoutes());
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_get_network', { serial: SN }));
    expect(Object.keys(out)).toEqual(expect.arrayContaining(['interfaces', 'dhcp', 'routes', 'vips', 'vpn']));
    expect(out.addresses).toBeUndefined();
    expect(fortiosCalls(calls).some((c) => c.url.pathname.endsWith('firewall/address'))).toBe(false);

    expect(out.dhcp.servers[0]).toEqual({
      id: 1,
      interface: 'internal',
      status: 'enable',
      ranges: ['192.168.10.100 - 192.168.10.199'],
      netmask: '255.255.255.0',
      gateway: '192.168.10.1',
      dns: { mode: 'specify', servers: ['192.168.10.1'] },
      leaseTimeSeconds: 604800,
      leaseTime: '7 d',
      activeLeases: 2,
    });
    expect(out.routes.source).toMatch(/^live/);
    expect(out.routes.defaultRoutes).toEqual([{ destination: '0.0.0.0/0', gateway: '198.51.100.21', interface: 'wan1', type: 'static', distance: 5, metric: 0, priority: 1 }]);
    expect(out.routes.routes[0].destination).toBe('0.0.0.0/0');
    expect(out.routes.byType).toEqual({ connect: 1, static: 1 });
    expect(out.vips.vips[0]).toMatchObject({ name: 'web-in', externalIp: '198.51.100.20', externalPort: '443', mappedIp: '192.168.10.20', mappedPort: '443', externalInterface: 'wan1' });
    const tunnels = Object.fromEntries(out.vpn.tunnels.map((t: any) => [t.name, t]));
    expect(tunnels['to-branch']).toMatchObject({ remoteGateway: '192.0.2.50', status: 'up', ikeVersion: '2', interface: 'wan1' });
    expect(tunnels['to-branch'].phase2[0]).toEqual({ name: 'to-branch', status: 'up', local: ['192.168.10.0/24'], remote: ['10.30.0.0/16'] });
    expect(tunnels['old-site']).toMatchObject({ remoteGateway: '192.0.2.60', status: 'down', phase2: [{ name: 'old-site', local: '192.168.10.0/24', remote: '10.40.0.0/16' }] });
    expect(out.vpn.up).toBe(1);

    const addr = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['addresses'] }));
    expect(addr.addresses.addresses).toEqual([
      { name: 'LAN', subnet: '192.168.10.0/24' },
      { name: 'pool', range: '10.0.0.5 - 10.0.0.9' },
    ]);
    expect(addr.addresses.byType).toEqual({ ipmask: 1, iprange: 1, fqdn: 1 });
  });

  it('routes fall back to static routes when the live table cannot be read', async () => {
    const { fn } = fakeForticloud(
      networkRoutes(SN, {
        [FOS(SN, 'monitor/router/ipv4')]: json({ status: 'error', http_status: 404 }, 404),
        [FOS(SN, 'cmdb/router/static')]: json(envelope([{ 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', gateway: '198.51.100.21', device: 'wan1', status: 'enable', distance: 10 }])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['routes'] }));
    expect(out.routes.source).toMatch(/^configured static routes/);
    expect(out.routes.liveError).toMatch(/404/);
    expect(out.routes.defaultRoutes[0]).toMatchObject({ destination: '0.0.0.0/0', gateway: '198.51.100.21', interface: 'wan1', type: 'static' });
  });

  it('an unreachable device: the first section fails and the rest are not tried; a 404 section does not stop the rest', async () => {
    const down = () => json({ message: 'Device is offline' }, 502);
    const { fn, calls } = fakeForticloud({
      [`${FGT}/devices`]: json(DEVICES),
      [`${FGT}/subaccounts`]: json(SUBACCOUNTS),
      [FOS(SN2, 'cmdb/system/interface')]: down,
      [FOS(SN2, 'monitor/system/interface')]: down,
    });
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_get_network', { serial: SN2 }));
    expect(out.warning).toMatch(/offline/);
    expect(out.interfaces.error).toMatch(/502/);
    for (const s of ['dhcp', 'routes', 'vips', 'vpn']) expect(out[s].skipped).toMatch(/not tried/);
    expect(fortiosCalls(calls)).toHaveLength(2);

    const { fn: fn2 } = fakeForticloud(networkRoutes(SN, { [FOS(SN, 'cmdb/system.dhcp/server')]: json({ status: 'error', http_status: 404 }, 404) }));
    setFetchForTests(fn2);
    const out2 = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['dhcp', 'vips'] }));
    expect(out2.dhcp.error).toMatch(/404/);
    expect(out2.vips.vips).toHaveLength(1);
  });

  it('an error FortiOS reports in the body is an error', async () => {
    const { fn } = fakeForticloud(networkRoutes(SN, { [FOS(SN, 'cmdb/firewall/vip')]: json({ status: 'error', http_status: 403, message: 'no permission' }) }));
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_get_network', { serial: SN, sections: ['vips'] }));
    expect(out.vips.error).toMatch(/FortiOS answered with an error \(HTTP 403\)/);
  });

  it('a 429 on a FortiOS read is a structured rate_limited error', async () => {
    const { fn } = fakeForticloud(networkRoutes(SN, { [FOS(SN, 'cmdb/firewall/vip')]: json({}, 429, { 'Retry-After': '120' }) }));
    setFetchForTests(fn);
    const res = await call('forticloud_get_network', { serial: SN });
    expect(res.structuredContent).toEqual({ error_type: 'rate_limited', retry_after_seconds: 120 });
  });
});

describe('forticloud_find_ip', () => {
  const C_CONFIG = [{ name: 'lan', type: 'physical', role: 'lan', ip: '192.168.10.1 255.255.255.0' }, { name: 'wan1', role: 'wan', mode: 'dhcp', ip: '0.0.0.0 0.0.0.0' }];
  const C_LIVE = { lan: { name: 'lan', ip: '192.168.10.1', mask: 24, link: true }, wan1: { name: 'wan1', ip: '198.51.100.40', mask: 29, link: true } };
  const fleet = (extra: Record<string, any> = {}) => ({
    ...networkRoutes(SN),
    [FOS(SN3, 'cmdb/system/interface')]: json(envelope(C_CONFIG)),
    [FOS(SN3, 'monitor/system/interface')]: json(envelope(C_LIVE)),
    ...extra,
  });

  it('finds the client, device, interface and VLAN for an IP; offline devices are listed, not queried', async () => {
    const { fn, calls } = fakeForticloud(fleet());
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_find_ip', { query: '10.20.0.55' }));
    expect(out.query).toBe('10.20.0.55');
    expect(out.results).toEqual([
      {
        account: 'Example Client A',
        device: 'client-a-fw',
        serial: SN,
        interface: 'vlan20',
        type: 'vlan',
        vlanId: 20,
        parent: 'internal',
        role: 'lan',
        interfaceAddress: '10.20.0.1/24',
        source: 'configured and live',
        match: 'inside the interface subnet',
      },
    ]);
    expect(out.devices).toEqual({ inScope: 3, online: 2, searched: 2, notQueried: 1 });
    expect(out.notQueriedDevices).toEqual([{ serial: SN2, device: 'client-b-fw', account: 'Example Client B', reason: 'offline in FortiGate Cloud' }]);
    expect(out.complete).toBeUndefined();
    expect(fortiosCalls(calls).some((c) => c.url.pathname.includes(SN2))).toBe(false);
  });

  it('a public WAN address (live only) is an exact match; a subnet matches overlapping interfaces on several clients', async () => {
    const { fn } = fakeForticloud(fleet());
    setFetchForTests(fn);
    const wan = dataOf(await call('forticloud_find_ip', { query: '198.51.100.40' }));
    expect(wan.results).toEqual([expect.objectContaining({ serial: SN3, interface: 'wan1', role: 'wan', interfaceAddress: '198.51.100.40/29', source: 'live', match: 'interface address', publicIp: true })]);
    const sub = dataOf(await call('forticloud_find_ip', { query: '192.168.0.0/16' }));
    expect(sub.results.map((r: any) => [r.serial, r.interface, r.match])).toEqual([
      [SN, 'internal', 'contains the interface subnet'],
      [SN3, 'lan', 'contains the interface subnet'],
    ]);
    const same = dataOf(await call('forticloud_find_ip', { query: '192.168.10.0/24', account: 'client c' }));
    expect(same.results).toEqual([expect.objectContaining({ serial: SN3, interface: 'lan', match: 'same subnet' })]);
    expect(same.devices).toMatchObject({ inScope: 1, online: 1 });
  });

  it('reuses each device for 10 minutes: a second call makes no FortiOS requests', async () => {
    const { fn, calls } = fakeForticloud(fleet());
    setFetchForTests(fn);
    await call('forticloud_find_ip', { query: '10.20.0.55' });
    const first = fortiosCalls(calls).length;
    expect(first).toBe(4);
    const again = dataOf(await call('forticloud_find_ip', { query: '203.0.113.3' }));
    expect(fortiosCalls(calls).length).toBe(first);
    expect(again.devices.fromCache).toBe(2);
    expect(again.results[0]).toMatchObject({ interface: 'dmz', match: 'inside the interface subnet', publicIp: true });
  });

  it('returns partial results when the time budget runs out, naming the skipped devices', async () => {
    FIND_IP_LIMITS.budgetMs = 150;
    FIND_IP_LIMITS.concurrency = 1;
    const slow = () => new Promise<Response>((r) => setTimeout(() => r(json(envelope(C_CONFIG))), 400));
    const { fn } = fakeForticloud(fleet({ [FOS(SN3, 'cmdb/system/interface')]: slow, [FOS(SN3, 'monitor/system/interface')]: slow }));
    setFetchForTests(fn);
    const started = Date.now();
    const out = dataOf(await call('forticloud_find_ip', { query: '192.168.10.5' }));
    expect(Date.now() - started).toBeLessThan(380);
    expect(out.complete).toBe(false);
    expect(out.stoppedBecause).toMatch(/time budget ran out/);
    expect(out.results.map((r: any) => r.serial)).toEqual([SN]);
    expect(out.skippedDevices).toEqual([{ serial: SN3, device: 'client-c-fw', account: 'Example Client C', reason: 'still reading when the budget ran out' }]);
    await new Promise((r) => setTimeout(r, 400));
  });

  it('stops asking after too many failed devices', async () => {
    FIND_IP_LIMITS.maxErrors = 1;
    FIND_IP_LIMITS.concurrency = 1;
    const down = () => json({ message: 'unreachable' }, 502);
    const { fn, calls } = fakeForticloud(fleet({ [FOS(SN, 'cmdb/system/interface')]: down, [FOS(SN, 'monitor/system/interface')]: down }));
    setFetchForTests(fn);
    const out = dataOf(await call('forticloud_find_ip', { query: '192.168.10.5' }));
    expect(out.failedDevices).toEqual([expect.objectContaining({ serial: SN, error: expect.stringMatching(/502/) })]);
    expect(out.stoppedBecause).toMatch(/1 devices failed/);
    expect(out.skippedDevices).toEqual([expect.objectContaining({ serial: SN3, reason: 'not reached' })]);
    expect(out.complete).toBe(false);
    expect(fortiosCalls(calls).some((c) => c.url.pathname.includes(SN3))).toBe(false);
  });

  it('a 429 stops the search with a structured rate_limited error', async () => {
    const { fn } = fakeForticloud(fleet({ [FOS(SN, 'cmdb/system/interface')]: json({}, 429, { 'Retry-After': '90' }) }));
    setFetchForTests(fn);
    const res = await call('forticloud_find_ip', { query: '192.168.10.5' });
    expect(res.structuredContent).toEqual({ error_type: 'rate_limited', retry_after_seconds: 90 });
  });

  it('refuses a query that is not an IPv4 address or subnet, or is wider than /8', async () => {
    const { fn } = fakeForticloud(fleet());
    setFetchForTests(fn);
    for (const query of ['example.com', '10.0.0.256', '10.0.0.0/33', '2001:db8::1']) {
      expect((await call('forticloud_find_ip', { query })).structuredContent).toMatchObject({ error_type: 'invalid_input' });
    }
    expect(textOf(await call('forticloud_find_ip', { query: '0.0.0.0/0' }))).toMatch(/\/8 or longer/);
    expect(fn).not.toHaveBeenCalled();
  });
});

describe('IP helpers', () => {
  it('parses FortiOS address forms', () => {
    expect(cidr(parseFortiosNet('192.168.1.1 255.255.255.0')!)).toBe('192.168.1.1/24');
    expect(cidr(parseFortiosNet('198.51.100.20', 30)!)).toBe('198.51.100.20/30');
    expect(cidr(parseFortiosNet('198.51.100.20', '255.255.255.252')!)).toBe('198.51.100.20/30');
    expect(parseFortiosNet('0.0.0.0 0.0.0.0')).toBeUndefined();
    expect(parseFortiosNet('10.0.0.1 255.0.255.0')).toBeUndefined();
    expect(subnetText('10.30.0.0/255.255.0.0')).toBe('10.30.0.0/16');
    expect(subnetText('10.30.1.7 255.255.0.0')).toBe('10.30.0.0/16');
    expect(parseIpv4('1.2.3')).toBeUndefined();
  });
  it('tells private from public', () => {
    for (const ip of ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '100.64.0.1', '100.127.255.254', '127.0.0.1', '169.254.1.1']) expect(isPrivate(parseIpv4(ip)!)).toBe(true);
    for (const ip of ['198.51.100.1', '203.0.113.9', '172.32.0.1', '100.128.0.1', '8.8.8.8']) expect(isPrivate(parseIpv4(ip)!)).toBe(false);
  });
  it('relates a query to an interface network', () => {
    const iface = parseFortiosNet('10.20.0.1 255.255.255.0')!;
    expect(relate(parseQuery('10.20.0.1')!, iface)).toBe('interface address');
    expect(relate(parseQuery('10.20.0.200')!, iface)).toBe('inside the interface subnet');
    expect(relate(parseQuery('10.20.0.128/25')!, iface)).toBe('inside the interface subnet');
    expect(relate(parseQuery('10.20.0.0/24')!, iface)).toBe('same subnet');
    expect(relate(parseQuery('10.0.0.0/8')!, iface)).toBe('contains the interface subnet');
    expect(relate(parseQuery('10.21.0.0/24')!, iface)).toBeUndefined();
    expect(relate(parseQuery('10.20.1.1')!, iface)).toBeUndefined();
  });
  it('shows a moment as local time with its zone', () => {
    expect(timeIn(Date.parse('2030-01-31T03:05:09Z'), 'Australia/Melbourne')).toBe('2030-01-31 14:05:09 Australia/Melbourne');
    expect(timeIn(Date.parse('2030-01-31T03:05:09Z'), 'UTC')).toBe('2030-01-31 03:05:09 UTC');
  });
});
