import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setFetchForTests } from '../client.js';
import { FORTIOS_ENDPOINTS, SECRET_NAME, filterFortios } from '../fortios.js';
import { clearCaches } from '../tools/format.js';
import { dispatchToolCall } from '../tools/index.js';
import { clearNetworkCaches } from '../tools/network.js';
import { FGT, dataOf, fakeForticloud, json, textOf } from './test-helpers.js';
import type { Call, Route } from './test-helpers.js';

const SN = 'FGT60FTK00000031';
const DEVICES = [{ sn: SN, name: 'example-fw', model: 'FortiGate 60F', firmwareVersion: '7.4.4', tunnelAlive: true, subAccountOid: 100 }];
const SUBACCOUNTS = [{ oid: 100, name: 'Example Client' }];

const envelope = (results: unknown) => ({ http_method: 'GET', results, vdom: 'root', status: 'success', http_status: 200, serial: SN, version: 'v7.4.4', build: 2662 });
const FOS = (path: string) => `${FGT}/fgt/${SN}/api/v2/${path}`;
const denied = () => json({ status: 'error', http_status: 403 }, 403);
const call = (args: Record<string, unknown>) => dispatchToolCall('forticloud_get_admin_access', args);
const fortiosCalls = (calls: Call[]) => calls.filter((c) => c.url.pathname.includes('/fgt/'));

/** Secret fields FortiOS returns on an admin, API user or SNMP entry; none may come back. */
const ADMIN_SECRETS = {
  password: 'SECRET-pw-1',
  'old-password': 'SECRET-pw-2',
  'ssh-public-key1': 'SECRET-sshkey-3',
  'ssh-public-key2': 'SECRET-sshkey-4',
  fortitoken: 'SECRET-token-5',
  'email-to': 'admin@example.com',
  'sms-phone': '+10000000000',
  'guest-usergroups': [{ name: 'SECRET-guests-6' }],
};
const UNSET4 = '0.0.0.0 0.0.0.0';
const admin = (name: string, trust: string[] = [], extra: Record<string, unknown> = {}) => ({
  name,
  accprofile: 'super_admin',
  vdom: [{ name: 'root' }],
  ...Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`trusthost${i + 1}`, trust[i] ?? UNSET4])),
  ...Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`ip6-trusthost${i + 1}`, '::/0'])),
  'two-factor': 'disable',
  wildcard: 'disable',
  'remote-group': '',
  ...ADMIN_SECRETS,
  ...extra,
});
const apiUser = (name: string, trust: string[] = []) => ({
  name,
  accprofile: 'read-only',
  vdom: [{ name: 'root' }],
  'api-key': 'SECRET-apikey-7',
  trusthost: trust.map((t, i) => ({ id: i + 1, type: 'ipv4-trusthost', 'ipv4-trustip': t, 'ipv6-trustip': '::/0' })),
});

const BASE: Record<string, Route | Response> = {
  'cmdb/system/global': json(
    envelope({
      'admin-sport': 8443,
      'admin-port': 80,
      'admin-ssh-port': 22,
      'admin-telnet': 'disable',
      'admin-https-redirect': 'enable',
      admintimeout: 15,
      'admin-lockout-threshold': 3,
      'admin-lockout-duration': 60,
      'admin-maintainer': 'enable',
      hostname: 'example-host',
      'admin-ssh-password': 'SECRET-global-8',
    })
  ),
  'cmdb/system/interface': json(
    envelope([
      { name: 'wan1', type: 'physical', role: 'wan', ip: '198.51.100.2 255.255.255.252', allowaccess: 'ping https ssh fgfm', alias: 'Fibre', 'pppoe-password': 'SECRET-pppoe-9' },
      { name: 'wan2', type: 'physical', role: 'wan', ip: '203.0.113.6 255.255.255.252', allowaccess: 'ping' },
      { name: 'internal', type: 'hard-switch', role: 'lan', ip: '192.168.1.99 255.255.255.0', allowaccess: 'ping https ssh http snmp' },
      { name: 'unused', type: 'physical', role: 'lan', ip: UNSET4, allowaccess: '' },
    ])
  ),
  'cmdb/system/admin': json(envelope([admin('admin')])),
  'cmdb/system/api-user': json(envelope([apiUser('example-api', ['192.0.2.10 255.255.255.255'])])),
  'cmdb/firewall/local-in-policy': json(envelope([])),
  'cmdb/system.snmp/community': json(
    envelope([
      {
        id: 1,
        name: 'SECRET-community-10',
        status: 'enable',
        'query-v1-status': 'disable',
        'query-v2c-status': 'enable',
        'trap-v1-status': 'disable',
        'trap-v2c-status': 'enable',
        hosts: [{ id: 1, ip: '192.168.1.50 255.255.255.255', interface: 'internal', 'host-type': 'any' }],
        hosts6: [],
      },
    ])
  ),
  'cmdb/system.snmp/user': json(
    envelope([
      { name: 'example-snmpv3', status: 'enable', 'security-level': 'auth-priv', queries: 'enable', 'query-port': 161, 'trap-status': 'enable', 'notify-hosts': '192.168.1.50', 'auth-proto': 'sha256', 'auth-pwd': 'SECRET-auth-11', 'priv-proto': 'aes256', 'priv-pwd': 'SECRET-priv-12' },
    ])
  ),
};

function routes(reads: Record<string, Route | Response>) {
  const out: Record<string, Route | Response> = { [`${FGT}/devices`]: json(DEVICES), [`${FGT}/subaccounts`]: json(SUBACCOUNTS) };
  for (const [path, r] of Object.entries({ ...BASE, ...reads })) out[FOS(path)] = r;
  return out;
}

function expectNoSecrets(res: Awaited<ReturnType<typeof call>>) {
  const t = textOf(res);
  expect(t).not.toContain('SECRET');
  for (const s of ['password', 'ssh-public-key', 'fortitoken', 'api-key', 'auth-pwd', 'priv-pwd', 'auth-proto', 'admin@example.com', '+10000000000']) expect(t).not.toContain(s);
}

const wan1 = (out: any) => out.summary.internetManagement.find((e: any) => e.interface === 'wan1');

beforeEach(() => {
  process.env.FORTICLOUD_API_ID = 'APIUSER0000000000000';
  process.env.FORTICLOUD_API_PASSWORD = 'Sup3r-Secret-Passw0rd!';
  for (const k of ['FORTICLOUD_AUTH_URL', 'FORTICLOUD_ASSET_URL', 'FORTICLOUD_FGT_URL', 'FORTICLOUD_UNTRUSTED_MARKERS', 'FORTICLOUD_TIME_ZONE']) delete process.env[k];
  clearCaches();
  clearNetworkCaches();
});
afterEach(() => setFetchForTests(undefined));

describe('forticloud_get_admin_access', () => {
  it('an admin with no trusted host and https on a WAN interface: reachable from the internet', async () => {
    const { fn, calls } = fakeForticloud(routes({}));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBeFalsy();
    expectNoSecrets(res);
    const out = dataOf(res);
    expect(fortiosCalls(calls)).toHaveLength(7);
    expect(out.complete).toBeUndefined();
    expect(wan1(out)).toMatchObject({ wanFacing: 'role wan', services: ['https (port 8443)', 'ssh'], internetManagement: 'yes' });
    expect(wan1(out).reason).toMatch(/admin has no trusted host, and no local-in policy denies it/);
    // wan2 allows only ping; the LAN interface is not WAN-facing.
    expect(out.summary.internetManagement.find((e: any) => e.interface === 'wan2')).toMatchObject({ internetManagement: 'no' });
    expect(out.summary.internetManagement.map((e: any) => e.interface)).toEqual(['wan1', 'wan2']);
    expect(out.adminSettings).toEqual({
      httpsPort: 8443,
      httpPort: 80,
      sshPort: 22,
      telnet: 'disable',
      httpsRedirect: 'enable',
      idleTimeoutMinutes: 15,
      lockoutThreshold: 3,
      lockoutDurationSeconds: 60,
      maintainerAccount: 'enable',
    });
    expect(out.interfaces.interfaces.map((i: any) => i.name)).toEqual(['wan1', 'wan2', 'internal']);
    expect(out.interfaces.interfaces[0]).toMatchObject({ alias: 'Fibre', ip: '198.51.100.2/30', management: ['https', 'ssh'], other: ['ping', 'fgfm'] });
    expect(out.administrators).toMatchObject({ total: 1, noTrustedHost: ['admin'] });
    expect(out.administrators.admins[0]).toEqual({ name: 'admin', profile: 'super_admin', vdoms: ['root'], anyIpv4Host: true, anyIpv6Host: true, twoFactor: 'disable', wildcard: 'disable' });
    expect(out.apiUsers.users[0]).toMatchObject({ name: 'example-api', trustedHosts: ['192.0.2.10/32'], anyIpv4Host: false, apiUser: true });
    // SNMP: communities by id (never the name, which is the community string), v3 users without keys.
    expect(out.snmp.communities.communities[0]).toEqual({
      id: 1,
      status: 'enable',
      queryV1: 'disable',
      queryV2c: 'enable',
      trapV1: 'disable',
      trapV2c: 'enable',
      hosts: [{ ip: '192.168.1.50/32', interface: 'internal', type: 'any' }],
    });
    expect(out.snmp.users.users[0]).toEqual({ name: 'example-snmpv3', status: 'enable', securityLevel: 'auth-priv', queries: 'enable', queryPort: 161, trapStatus: 'enable', notifyHosts: '192.168.1.50' });
  });

  it('every administrator and API user with trusted hosts: restricted, with the hosts named', async () => {
    const { fn } = fakeForticloud(
      routes({
        'cmdb/system/admin': json(envelope([admin('admin', ['203.0.113.0 255.255.255.0']), admin('example-tech', ['192.0.2.0 255.255.255.128', UNSET4])])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(wan1(out).internetManagement).toBe('restricted');
    expect(wan1(out).reason).toBe('https (port 8443), ssh allowed, but every administrator and REST API user has trusted hosts: 203.0.113.0/24, 192.0.2.0/25, 192.0.2.10/32');
    expect(out.administrators.noTrustedHost).toEqual([]);
  });

  it('a trusted host of 0.0.0.0/0 counts as none', async () => {
    const { fn } = fakeForticloud(routes({ 'cmdb/system/admin': json(envelope([admin('admin', ['0.0.0.0 0.0.0.0', '0.0.0.0/0'])])) }));
    setFetchForTests(fn);
    expect(wan1(dataOf(await call({ serial: SN }))).internetManagement).toBe('yes');
  });

  it('a local-in deny from everywhere restricts it, naming the sources let in first', async () => {
    const { fn, calls } = fakeForticloud(
      routes({
        'cmdb/firewall/local-in-policy': json(
          envelope([
            { policyid: 1, intf: [{ name: 'wan1' }], srcaddr: [{ name: 'mgmt-hosts' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], action: 'accept', schedule: 'always', status: 'enable' },
            { policyid: 2, intf: [{ name: 'wan1' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], action: 'deny', schedule: 'always', status: 'enable' },
          ])
        ),
        'cmdb/firewall/address': json(envelope([{ name: 'mgmt-hosts', type: 'ipmask', subnet: '203.0.113.0 255.255.255.0' }])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(fortiosCalls(calls)).toHaveLength(8);
    expect(wan1(out)).toMatchObject({ internetManagement: 'restricted' });
    expect(wan1(out).reason).toBe('https (port 8443), ssh allowed, but local-in policy 2 denies IPv4 sign-ins from everywhere except mgmt-hosts (203.0.113.0/24)');
    expect(out.localInPolicies.policies[0]).toMatchObject({ id: 1, interfaces: ['wan1'], sources: ['mgmt-hosts (203.0.113.0/24)'], action: 'accept' });
  });

  const denyAll = (id: number, dst = 'all') => ({ policyid: id, intf: [{ name: 'wan1' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: dst }], service: [{ name: 'ALL' }], action: 'deny', schedule: 'always', status: 'enable' });

  it('an earlier local-in accept from all leaves it open, whatever deny follows', async () => {
    const { fn } = fakeForticloud(
      routes({
        'cmdb/firewall/local-in-policy': json(
          envelope([{ policyid: 1, intf: [{ name: 'wan1' }], srcaddr: [{ name: 'all' }], dstaddr: [{ name: 'all' }], service: [{ name: 'HTTPS' }, { name: 'SSH' }], action: 'accept', schedule: 'always', status: 'enable' }, denyAll(2)])
        ),
      })
    );
    setFetchForTests(fn);
    expect(wan1(dataOf(await call({ serial: SN }))).internetManagement).toBe('yes');
  });

  it('an IPv4 local-in deny does not restrict IPv6 sign-ins', async () => {
    const { fn } = fakeForticloud(
      routes({
        'cmdb/system/interface': json(
          envelope([{ name: 'wan1', role: 'wan', ip: '198.51.100.2 255.255.255.252', allowaccess: 'https', ipv6: { 'ip6-address': '2001:db8::2/64', 'ip6-allowaccess': 'https' } }])
        ),
        'cmdb/system/admin': json(envelope([admin('admin', ['203.0.113.0 255.255.255.0'])])),
        'cmdb/firewall/local-in-policy': json(envelope([denyAll(1)])),
      })
    );
    setFetchForTests(fn);
    const e = wan1(dataOf(await call({ serial: SN })));
    expect(e.internetManagement).toBe('yes');
    expect(e.reason).toBe('https (port 8443) allowed; local-in policy 1 denies IPv4 sign-ins from everywhere; on IPv6 admin, example-api (REST API) have no trusted host (IPv6; IPv6 local-in policies are not read)');
  });

  it('a local-in deny to the primary address only does not cover a secondary address with https', async () => {
    const iface = json(
      envelope([{ name: 'wan1', role: 'wan', ip: '198.51.100.2 255.255.255.252', allowaccess: 'ping', secondaryip: [{ id: 1, ip: '198.51.100.6 255.255.255.252', allowaccess: 'https' }] }])
    );
    const { fn } = fakeForticloud(
      routes({
        'cmdb/system/interface': iface,
        'cmdb/firewall/local-in-policy': json(envelope([denyAll(1, 'wan1-primary')])),
        'cmdb/firewall/address': json(envelope([{ name: 'wan1-primary', type: 'ipmask', subnet: '198.51.100.2 255.255.255.255' }])),
      })
    );
    setFetchForTests(fn);
    expect(wan1(dataOf(await call({ serial: SN }))).internetManagement).toBe('yes');

    // A deny to both addresses restricts it.
    const { fn: fn2 } = fakeForticloud(
      routes({
        'cmdb/system/interface': iface,
        'cmdb/firewall/local-in-policy': json(envelope([denyAll(1, 'wan1-block')])),
        'cmdb/firewall/address': json(envelope([{ name: 'wan1-block', type: 'ipmask', subnet: '198.51.100.0 255.255.255.248' }])),
      })
    );
    setFetchForTests(fn2);
    expect(wan1(dataOf(await call({ serial: SN }))).internetManagement).toBe('restricted');
  });

  it('a local-in deny for one source only does not restrict it', async () => {
    const { fn } = fakeForticloud(
      routes({
        'cmdb/firewall/local-in-policy': json(
          envelope([{ policyid: 1, intf: [{ name: 'wan1' }], srcaddr: [{ name: 'bad-host' }], dstaddr: [{ name: 'all' }], service: [{ name: 'ALL' }], action: 'deny', schedule: 'always', status: 'enable' }])
        ),
        'cmdb/firewall/address': json(envelope([{ name: 'bad-host', type: 'ipmask', subnet: '198.51.100.99 255.255.255.255' }])),
      })
    );
    setFetchForTests(fn);
    expect(wan1(dataOf(await call({ serial: SN }))).internetManagement).toBe('yes');
  });

  it('a 403 on the administrators makes the verdict unknown and names the HTTP status; the rest still shows', async () => {
    const { fn } = fakeForticloud(routes({ 'cmdb/system/admin': denied() }));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBeFalsy();
    const out = dataOf(res);
    expect(out.complete).toBe(false);
    expect(out.unreadable).toEqual([{ read: 'cmdb system/admin', reason: 'permission_denied', httpStatus: 403 }]);
    expect(out.administrators).toMatchObject({ read: 'cmdb system/admin', reason: 'permission_denied', httpStatus: 403, note: 'unavailable' });
    expect(wan1(out).internetManagement).toBe('unknown');
    expect(wan1(out).reason).toMatch(/cmdb system\/admin \(permission_denied, HTTP 403\) could not be read in full/);
    // An interface with no sign-in service does not depend on the administrators.
    expect(out.summary.internetManagement.find((e: any) => e.interface === 'wan2').internetManagement).toBe('no');
    expect(out.interfaces.total).toBe(4);
  });

  it('an unreadable local-in list keeps an open admin unknown, not yes', async () => {
    const { fn } = fakeForticloud(routes({ 'cmdb/firewall/local-in-policy': denied() }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(wan1(out).internetManagement).toBe('unknown');
    expect(wan1(out).reason).toMatch(/local-in policies could not be checked \(permission_denied, HTTP 403\)/);
  });

  it('an unreachable device: nothing after the first read is tried', async () => {
    const { fn, calls } = fakeForticloud(routes({ 'cmdb/system/global': json({ error: 'gateway' }, 502) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(fortiosCalls(calls)).toHaveLength(1);
    expect(out.summary.text).toMatch(/^Management exposure unknown/);
    expect(out.summary.internetManagement).toEqual([]);
  });

  it('allowlists: no secret field is kept, and no allowlisted name looks like one', () => {
    const a = filterFortios(envelope([admin('x')]), FORTIOS_ENDPOINTS.admins).rows[0];
    for (const k of Object.keys(ADMIN_SECRETS)) expect(a).not.toHaveProperty(k);
    const u = filterFortios(envelope([apiUser('y')]), FORTIOS_ENDPOINTS.apiUsers).rows[0];
    expect(u).not.toHaveProperty('api-key');
    const c = filterFortios(envelope([{ id: 1, name: 'SECRET-c' }]), FORTIOS_ENDPOINTS.snmpCommunities).rows[0];
    expect(c).toEqual({ id: 1 });
    const fields = ['adminGlobal', 'adminInterfaces', 'admins', 'apiUsers', 'localIn', 'snmpCommunities', 'snmpUsers'].flatMap((e) =>
      JSON.stringify(FORTIOS_ENDPOINTS[e as keyof typeof FORTIOS_ENDPOINTS].fields).match(/"[^"]+":/g)!.map((k) => k.slice(1, -2))
    );
    expect(fields.filter((n) => SECRET_NAME.test(n))).toEqual([]);
  });
});
