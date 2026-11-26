import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setFetchForTests } from '../client.js';
import { FORTIOS_ENDPOINTS, MAX_NESTED, SECRET_NAME, filterFortios } from '../fortios.js';
import { clearCaches } from '../tools/format.js';
import { ALL_TOOLS, dispatchToolCall } from '../tools/index.js';
import { clearNetworkCaches } from '../tools/network.js';
import { FGT, dataOf, fakeForticloud, json, textOf } from './test-helpers.js';
import type { Call, Route } from './test-helpers.js';

const SN = 'FGT60FTK00000021';
const SN_DOWN = 'FGT40FTK00000023';
const DEVICES = [
  { sn: SN, name: 'example-fw', model: 'FortiGate 60F', firmwareVersion: '7.4.4', tunnelAlive: true, subAccountOid: 100 },
  { sn: SN_DOWN, name: 'example-down-fw', model: 'FortiGate 40F', firmwareVersion: '7.2.8', tunnelAlive: false, subAccountOid: 100 },
];
const SUBACCOUNTS = [{ oid: 100, name: 'Example Client' }];

/** Secret fields FortiOS returns on a phase 1 (and might add elsewhere); none may come back. */
const P1_SECRETS = {
  psksecret: 'SECRET-psk-1',
  'psksecret-remote': 'SECRET-psk-2',
  'auto-discovery-psk': 'SECRET-advpn-3',
  certificate: [{ name: 'SECRET-cert-4' }],
  'ppk-secret': 'SECRET-ppk-5',
  authpasswd: 'SECRET-xauth-6',
  authusr: 'example-xauth-user',
  peerid: 'example-peer-id',
  'eap-identity': 'SECRET-eap-7',
};

const envelope = (results: unknown, version = 'v7.4.4') => ({ http_method: 'GET', results, vdom: 'root', status: 'success', http_status: 200, serial: SN, version, build: 2662 });
const FOS = (sn: string, path: string) => `${FGT}/fgt/${sn}/api/v2/${path}`;
const notFound = () => json({ status: 'error', http_status: 404 }, 404);
const call = (args: Record<string, unknown>) => dispatchToolCall('forticloud_get_vpn', args);
const fortiosCalls = (calls: Call[]) => calls.filter((c) => c.url.pathname.includes('/fgt/'));

// --- A primary (fibre) and backup (4G) tunnel to one site, 203.0.113.0/24 -----------------------------

const phase1 = (name: string, extra: Record<string, unknown> = {}) => ({
  name,
  type: 'static',
  interface: name.endsWith('4g') ? 'wan2' : 'wan1',
  'ike-version': '2',
  'remote-gw': '198.51.100.10',
  'mode-cfg': 'disable',
  monitor: [],
  dpd: 'on-idle',
  'dpd-retrycount': 3,
  'dpd-retryinterval': '20',
  'idle-timeout': 'disable',
  'auto-negotiate': 'enable',
  keepalive: 10,
  'net-device': 'disable',
  'add-route': 'disable',
  'exchange-interface-ip': 'disable',
  'auto-discovery-sender': 'disable',
  'auto-discovery-receiver': 'disable',
  comments: '',
  ...P1_SECRETS,
  ...extra,
});
const BACKUP = { monitor: [{ name: 'to-hq-fibre' }], 'monitor-hold-down-type': 'delay', 'monitor-hold-down-delay': 60 };
const phase2 = (p1: string, dst = '203.0.113.0 255.255.255.0', name = `${p1}-p2`) => ({
  name,
  phase1name: p1,
  'src-addr-type': 'subnet',
  'src-subnet': '192.0.2.0 255.255.255.0',
  'dst-addr-type': 'subnet',
  'dst-subnet': dst,
  'auto-negotiate': 'enable',
  keepalive: 'enable',
});
const sa = (p2name: string, status: 'up' | 'down', dst = '203.0.113.0/255.255.255.0') => ({
  p2name,
  status,
  expire: status === 'up' ? 1200 : 0,
  incoming_bytes: status === 'up' ? 1000 : 0,
  outgoing_bytes: status === 'up' ? 2000 : 0,
  proxy_src: [{ subnet: '192.0.2.0/255.255.255.0', port: 0, protocol: 0 }],
  proxy_dst: [{ subnet: dst, port: 0, protocol: 0 }],
});
const liveTunnel = (name: string, sas: unknown[]) => ({
  name,
  rgwy: '198.51.100.10',
  type: 'automatic',
  incoming_bytes: 5000,
  outgoing_bytes: 7000,
  creation_time: 3600,
  connection_count: 1,
  username: 'example-dialup-user',
  proxyid: sas,
});
const route = (seq: number, device: string, distance: number, dst = '203.0.113.0 255.255.255.0') => ({ 'seq-num': seq, dst, device, distance, priority: 0, status: 'enable' });

const HEALTHY: Record<string, Route | Response> = {
  'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g', BACKUP)])),
  'cmdb/vpn.ipsec/phase2-interface': json(envelope([phase2('to-hq-fibre'), phase2('to-hq-4g')])),
  'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])),
  'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-4g', 15), route(3, 'wan1', 10, '0.0.0.0 0.0.0.0')])),
};

/** A FortiGate with the healthy pair; each scenario overrides the reads that differ. */
function vpnRoutes(sn: string, reads: Record<string, Route | Response>) {
  const base: Record<string, Route | Response> = {
    [`${FGT}/devices`]: json(DEVICES),
    [`${FGT}/subaccounts`]: json(SUBACCOUNTS),
    [FOS(sn, 'cmdb/system/interface')]: json(envelope([{ name: 'wan1', type: 'physical', ip: '198.51.100.2 255.255.255.252' }])),
    [FOS(sn, 'monitor/virtual-wan/members')]: json(envelope({})),
    [FOS(sn, 'cmdb/router/bgp')]: json(envelope({ as: '0', 'router-id': '0.0.0.0', neighbor: [], 'neighbor-group': [], 'neighbor-range': [] })),
    [FOS(sn, 'monitor/router/bgp/neighbors')]: json(envelope([])),
    [FOS(sn, 'cmdb/vpn.ssl/settings')]: json(envelope({ status: 'enable', port: 10443, 'source-interface': [{ name: 'wan1' }], servercert: 'SECRET-sslcert' })),
    [FOS(sn, 'monitor/vpn/ssl')]: json(envelope([{ index: 0, user_name: 'example-ssl-user', remote_host: '198.51.100.77', last_login_time: 'x' }])),
  };
  const out: Record<string, Route | Response> = { ...base };
  for (const [path, r] of Object.entries({ ...HEALTHY, ...reads })) out[FOS(sn, path)] = r;
  return out;
}

function expectNoSecrets(res: Awaited<ReturnType<typeof call>>) {
  const t = textOf(res);
  expect(t).not.toContain('SECRET');
  for (const s of ['psksecret', 'auto-discovery-psk', 'certificate', 'authpasswd', 'example-xauth-user', 'example-peer-id', 'example-dialup-user', 'example-ssl-user', '198.51.100.77']) expect(t).not.toContain(s);
}

beforeEach(() => {
  process.env.FORTICLOUD_API_ID = 'APIUSER0000000000000';
  process.env.FORTICLOUD_API_PASSWORD = 'Sup3r-Secret-Passw0rd!';
  for (const k of ['FORTICLOUD_AUTH_URL', 'FORTICLOUD_ASSET_URL', 'FORTICLOUD_FGT_URL', 'FORTICLOUD_UNTRUSTED_MARKERS', 'FORTICLOUD_TIME_ZONE']) delete process.env[k];
  clearCaches();
  clearNetworkCaches();
});
afterEach(() => setFetchForTests(undefined));

describe('forticloud_get_vpn', () => {
  it('is listed as a read-only tool with serial, tunnel, max_rows and vdom', () => {
    const tool = ALL_TOOLS.find((t) => t.name === 'forticloud_get_vpn')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    expect(Object.keys(tool.inputSchema.properties ?? {})).toEqual(['serial', 'tunnel', 'max_rows', 'vdom']);
    expect(tool.inputSchema.required).toEqual(['serial']);
  });

  it('a healthy primary/backup pair: primary up, backup idle, routes 10/15, failover should work', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, {}));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBeFalsy();
    expectNoSecrets(res);
    const out = dataOf(res);
    expect(out.device).toMatchObject({ serial: SN, name: 'example-fw', account: 'Example Client' });
    expect(out.complete).toBeUndefined();
    expect(out.summary.text).toBe('2 IPsec tunnels (1 up, 0 partially up, 1 down), 1 primary/backup pair (phase 1 monitor), 0 problems.');
    expect(out.summary.sites).toEqual([
      'to-hq-fibre / to-hq-4g: primary to-hq-fibre up (DPD on-idle 3x20s); backup to-hq-4g idle (monitor of to-hq-fibre, fails back 60 s after the primary returns); routes 203.0.113.0/24 distance 10/15. Failover should work.',
    ]);
    expect(out.summary.caveats).toBeUndefined();
    expect(out.pairs).toEqual([
      {
        primary: 'to-hq-fibre',
        backup: 'to-hq-4g',
        backupOnlyWhenPrimaryDown: true,
        holdDown: 'fails back 60 s after the primary returns',
        primaryState: 'up',
        backupState: 'idle',
        state: 'primary up, backup idle',
        healthy: true,
      },
    ]);
    const [fibre, lte] = out.tunnels.tunnels;
    expect(fibre).toMatchObject({
      name: 'to-hq-fibre',
      configured: true,
      type: 'static',
      interface: 'wan1',
      remoteGateway: '198.51.100.10',
      ikeVersion: '2',
      modeCfg: 'disable',
      dpd: { mode: 'on-idle', retryCount: 3, retryIntervalSeconds: 20 },
      idleTimeout: { enabled: false },
      autoNegotiate: 'enable',
      natKeepaliveSeconds: 10,
      netDevice: 'disable',
      addRoute: 'disable',
      exchangeInterfaceIp: 'disable',
      status: 'up',
      live: { remoteGateway: '198.51.100.10', incomingBytes: 5000, outgoingBytes: 7000, creationTime: 3600, connections: 1 },
      routes: [{ seq: 1, destination: '203.0.113.0/24', distance: 10, priority: 0, status: 'enable' }],
    });
    expect(fibre.backupOf).toBeUndefined();
    expect(fibre.advpn).toBeUndefined();
    expect(fibre.phase2).toEqual([
      {
        name: 'to-hq-fibre-p2',
        local: '192.0.2.0/24',
        remote: '203.0.113.0/24',
        autoNegotiate: 'enable',
        keepalive: 'enable',
        state: 'up',
        liveLocal: '192.0.2.0/24',
        liveRemote: '203.0.113.0/24',
        incomingBytes: 1000,
        outgoingBytes: 2000,
        expiresInSeconds: 1200,
      },
    ]);
    expect(lte).toMatchObject({ name: 'to-hq-4g', backupOf: ['to-hq-fibre'], holdDown: { type: 'delay', delaySeconds: 60 }, status: 'down' });
    expect(out.tunnels.source).toEqual({
      configured: 'cmdb vpn.ipsec/phase1-interface + phase2-interface',
      live: 'monitor vpn/ipsec',
      routes: 'cmdb router/static',
      sdwanMembers: 'monitor virtual-wan/members',
    });
    expect(out.sslVpn).toMatchObject({ enabled: true, port: 10443, listensOn: ['wan1'], usersConnected: 1 });
    expect(out.bgp).toMatchObject({ total: 0, neighbors: [] });
  });

  it('a backup with no route: it will come up but carry no traffic', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10)])) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.pairs[0]).toMatchObject({ state: 'primary up, backup idle', healthy: false, problems: ['backup to-hq-4g has no route using it: it will come up but carry no traffic'] });
    expect(out.summary.sites[0]).toMatch(/routes 203\.0\.113\.0\/24 distance 10 \(only via to-hq-fibre\)\. Problems: backup to-hq-4g has no route using it: it will come up but carry no traffic\.$/);
    expect(out.summary.text).toMatch(/1 problem\.$/);
    expect(out.summary.caveats).toEqual([expect.stringMatching(/^Policy routes are not read/)]);

    // A backup whose /24 covers the primary's /25: no problem.
    const { fn: fn2 } = fakeForticloud(
      vpnRoutes(SN, { 'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-fibre', 10, '203.0.113.128 255.255.255.128'), route(3, 'to-hq-4g', 15)])) })
    );
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.pairs[0]).toMatchObject({ state: 'primary up, backup idle', healthy: true });
    expect(out2.pairs[0].problems).toBeUndefined();

    // A backup with routes to only some of the primary's subnets (a subnet its routes do not cover).
    const { fn: fn3 } = fakeForticloud(
      vpnRoutes(SN, { 'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-fibre', 10, '198.51.100.0 255.255.255.0'), route(3, 'to-hq-4g', 15)])) })
    );
    setFetchForTests(fn3);
    const out3 = dataOf(await call({ serial: SN }));
    expect(out3.pairs[0].problems).toEqual(['backup to-hq-4g has no route to 198.51.100.0/24, which the primary carries']);
  });

  it('DPD disabled on the primary: failover is slow or never happens', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre', { dpd: 'disable' }), phase1('to-hq-4g', BACKUP)])) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.tunnels.tunnels[0].dpd).toMatchObject({ mode: 'disable' });
    expect(out.pairs[0].problems).toEqual([
      'DPD is off on primary to-hq-fibre: a dead tunnel is noticed only when its interface goes down or IKE renegotiates, so failover is slow or never happens',
    ]);
    expect(out.summary.sites[0]).toMatch(/^to-hq-fibre \/ to-hq-4g: primary to-hq-fibre up \(DPD off\);/);
  });

  it('both tunnels down: no tunnel to the site', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, { 'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'down')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])) })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.pairs[0]).toMatchObject({ state: 'both down', healthy: false, problems: ['both to-hq-fibre and to-hq-4g are down: no tunnel to this site'] });
    expect(out.summary.text).toMatch(/^2 IPsec tunnels \(0 up, 0 partially up, 2 down\)/);
    expect(out.summary.sites[0]).toMatch(/Problems: both to-hq-fibre and to-hq-4g are down/);

    // Failed over, and both up (the backup during its hold-down).
    const { fn: fn2 } = fakeForticloud(
      vpnRoutes(SN, { 'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'down')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])) })
    );
    setFetchForTests(fn2);
    expect(dataOf(await call({ serial: SN })).pairs[0]).toMatchObject({ state: 'failed over: primary down, backup up', problems: ['primary to-hq-fibre is down: traffic is on the backup'] });
    const { fn: fn3 } = fakeForticloud(
      vpnRoutes(SN, { 'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])) })
    );
    setFetchForTests(fn3);
    expect(dataOf(await call({ serial: SN })).pairs[0].problems).toEqual([
      'backup to-hq-4g is up while the primary is up: expected only during the hold-down after the primary came back (fails back 60 s after the primary returns)',
    ]);
  });

  it('partially up: some phase 2 selectors up, a configured selector not negotiated', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase2-interface': json(
          envelope([phase2('to-hq-fibre'), phase2('to-hq-fibre', '203.0.113.128 255.255.255.128', 'to-hq-fibre-voice'), phase2('to-hq-fibre', '198.51.100.64 255.255.255.192', 'to-hq-fibre-mgmt'), phase2('to-hq-4g')])
        ),
        'monitor/vpn/ipsec': json(
          envelope([
            liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up'), sa('to-hq-fibre-voice', 'down', '203.0.113.128/255.255.255.128')]),
            liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')]),
          ])
        ),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const fibre = out.tunnels.tunnels[0];
    expect(fibre).toMatchObject({ status: 'partially up', phase2Up: 1, phase2Count: 3 });
    expect(fibre.phase2.map((p: any) => [p.name, p.state])).toEqual([
      ['to-hq-fibre-p2', 'up'],
      ['to-hq-fibre-voice', 'down'],
      ['to-hq-fibre-mgmt', 'not negotiated'],
    ]);
    expect(out.summary.text).toMatch(/\(0 up, 1 partially up, 1 down\)/);
    expect(out.pairs[0].primaryState).toBe('partially up (1 of 3 phase 2 up)');
    expect(out.pairs[0].problems).toEqual([
      'primary to-hq-fibre is only partly up (1 of 3 phase 2 up): the backup stays idle while any of the primary is up, so the down selectors have no path',
    ]);
  });

  it('BGP over IPsec: neighbors matched to tunnels by address, interface or range; BGP counts as a route', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([])),
        'cmdb/system/interface': json(
          envelope([
            { name: 'to-hq-fibre', type: 'tunnel', ip: '192.0.2.253 255.255.255.255', 'remote-ip': '192.0.2.254 255.255.255.252' },
            { name: 'to-hq-4g', type: 'tunnel', ip: '192.0.2.249 255.255.255.255', 'remote-ip': '192.0.2.250 255.255.255.252' },
          ])
        ),
        'cmdb/router/bgp': json(
          envelope({
            as: '65001',
            'router-id': '192.0.2.1',
            neighbor: [
              { ip: '192.0.2.254', 'remote-as': '65000', password: 'SECRET-bgp-1', description: 'hub over fibre' },
              { ip: '198.51.100.200', 'remote-as': '65000', 'update-source': 'to-hq-4g', password: 'SECRET-bgp-2' },
              { ip: '198.51.100.250', 'remote-as': '65009', interface: 'wan1' },
            ],
            'neighbor-group': [{ name: 'spokes', 'remote-as': '65002', interface: 'to-hq-4g', password: 'SECRET-bgp-3' }],
            'neighbor-range': [{ id: 1, prefix: '203.0.113.0 255.255.255.0', 'neighbor-group': 'spokes' }],
          })
        ),
        'monitor/router/bgp/neighbors': json(
          envelope([
            { neighbor_ip: '192.0.2.254', local_ip: '192.0.2.253', remote_as: 65000, admin_status: true, state: 'Established', type: 'ipv4' },
            { neighbor_ip: '198.51.100.200', local_ip: '192.0.2.249', remote_as: 65000, admin_status: true, state: 'Connect', type: 'ipv4' },
            { neighbor_ip: '203.0.113.5', local_ip: '192.0.2.249', remote_as: 65002, admin_status: true, state: 'Established', type: 'ipv4' },
          ])
        ),
      })
    );
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expectNoSecrets(res);
    const out = dataOf(res);
    expect(out.bgp).toMatchObject({ as: '65001', routerId: '192.0.2.1', total: 4, overTunnels: 3 });
    expect(out.bgp.neighbors.map((n: any) => [n.ip, n.tunnel, n.state])).toEqual([
      ['192.0.2.254', 'to-hq-fibre', 'Established'],
      ['198.51.100.200', 'to-hq-4g', 'Connect'],
      ['198.51.100.250', undefined, 'not in the live neighbor list'],
      ['203.0.113.5', 'to-hq-4g', 'Established'],
    ]);
    expect(out.bgp.neighbors[0]).toMatchObject({ remoteAs: '65000', description: 'hub over fibre', adminStatus: 'up', localIp: '192.0.2.253' });
    expect(out.bgp.neighbors[3]).toMatchObject({ dynamic: true, neighborGroup: 'spokes', remoteAs: 65002 });
    expect(out.bgp.neighborRanges).toEqual([{ prefix: '203.0.113.0/24', neighborGroup: 'spokes' }]);
    expect(out.tunnels.tunnels[0].bgpNeighbors).toEqual(['192.0.2.254']);
    // No static route, but BGP runs over both tunnels: no "no route" problem.
    expect(out.pairs[0]).toMatchObject({ state: 'primary up, backup idle', healthy: true });
    expect(out.summary.sites[0]).toMatch(/; BGP 192\.0\.2\.254 over to-hq-fibre Established, 198\.51\.100\.200 over to-hq-4g Connect, 203\.0\.113\.5 over to-hq-4g Established\. Failover should work\.$/);
  });

  it('a BGP endpoint that answers 404 is not_supported; the rest still shows', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'monitor/router/bgp/neighbors': notFound }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.complete).toBe(false);
    expect(out.unreadable).toEqual([{ read: 'monitor router/bgp/neighbors', reason: 'not_supported' }]);
    expect(out.bgp.liveError).toMatchObject({ read: 'monitor router/bgp/neighbors', reason: 'not_supported' });
    expect(out.bgp.source).toEqual({ configured: 'cmdb router/bgp' });
    expect(out.pairs[0]).toMatchObject({ healthy: true });

    // Both BGP reads 404 (and SSL-VPN not on this model): the sections say so.
    const { fn: fn2 } = fakeForticloud(
      vpnRoutes(SN, { 'monitor/router/bgp/neighbors': notFound, 'cmdb/router/bgp': notFound, 'cmdb/vpn.ssl/settings': notFound, 'monitor/vpn/ssl': notFound })
    );
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.bgp).toMatchObject({ read: 'cmdb router/bgp', reason: 'not_supported', liveError: { reason: 'not_supported' } });
    expect(out2.sslVpn).toMatchObject({ reason: 'not_supported' });
    expect(out2.summary.caveats).toEqual([expect.stringMatching(/^BGP could not be read \(not_supported\)/)]);
    expect(out2.summary.sites[0]).toMatch(/Failover should work\.$/);
  });

  it('never returns pre-shared keys, certificates or credentials, and the allowlists name none', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, {}));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expectNoSecrets(res);
    const p1 = filterFortios(envelope([phase1('t')]), FORTIOS_ENDPOINTS.vpnPhase1).rows[0];
    for (const k of Object.keys(P1_SECRETS)) expect(p1).not.toHaveProperty(k);
    const bgp = filterFortios(envelope({ neighbor: [{ ip: '192.0.2.9', password: 'SECRET-x' }] }), FORTIOS_ENDPOINTS.bgpConfig).rows[0];
    expect(bgp).toEqual({ neighbor: [{ ip: '192.0.2.9' }] });
    const ssl = filterFortios(envelope({ status: 'enable', servercert: 'SECRET-y' }), FORTIOS_ENDPOINTS.sslVpnConfig).rows[0];
    expect(ssl).toEqual({ status: 'enable' });
    const fields = ['vpnPhase1', 'vpnPhase2', 'vpnIpsecLive', 'bgpConfig', 'bgpLive', 'sslVpnConfig', 'sslVpnLive'].flatMap((e) =>
      JSON.stringify(FORTIOS_ENDPOINTS[e as keyof typeof FORTIOS_ENDPOINTS].fields).match(/"[^"]+":/g)!.map((k) => k.slice(1, -2))
    );
    expect(fields.filter((n) => SECRET_NAME.test(n))).toEqual([]);
  });

  it('a 429 on the first read is the structured rate_limited error; a later one marks only the reads it stopped', async () => {
    const { fn, calls } = fakeForticloud(vpnRoutes(SN, { 'cmdb/vpn.ipsec/phase1-interface': json({}, 429, { 'Retry-After': '120' }) }));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toEqual({ error_type: 'rate_limited', retry_after_seconds: 120 });
    expect(fortiosCalls(calls)).toHaveLength(1);

    // Nine reads after phase 1; six get a slot. The static routes answer 429 at once, so the three
    // queued ones (BGP neighbors, SSL-VPN settings and sessions) are never sent.
    const slow = (body: unknown) => async () => {
      await new Promise((r) => setTimeout(r, 40));
      return json(body);
    };
    const { fn: fn2, calls: calls2 } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json({}, 429, { 'Retry-After': '90' }),
        'cmdb/vpn.ipsec/phase2-interface': slow(envelope([phase2('to-hq-fibre'), phase2('to-hq-4g')])),
        'monitor/vpn/ipsec': slow(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])),
      })
    );
    setFetchForTests(fn2);
    const res2 = await call({ serial: SN });
    expect(res2.isError).toBeFalsy();
    const out = dataOf(res2);
    const sent = fortiosCalls(calls2).map((c) => c.url.pathname.split('/api/v2/')[1]);
    for (const p of ['monitor/router/bgp/neighbors', 'cmdb/vpn.ssl/settings', 'monitor/vpn/ssl']) expect(sent).not.toContain(p);
    expect(out.complete).toBe(false);
    expect(out.rateLimited).toMatchObject({ retryAfterSeconds: 90 });
    expect(out.rateLimited.note).toMatch(/Try again in 90 s/);
    expect(out.unreadable).toEqual(
      expect.arrayContaining([
        { read: 'cmdb router/static', reason: 'rate_limited', retryAfterSeconds: 90 },
        { read: 'monitor router/bgp/neighbors', reason: 'rate_limited', retryAfterSeconds: 90 },
        { read: 'monitor vpn/ssl', reason: 'rate_limited', retryAfterSeconds: 90 },
      ])
    );
    expect(out.tunnels.routesError).toMatchObject({ reason: 'rate_limited' });
    expect(out.bgp.liveError.error).toMatch(/^not asked/);
    // Routes unknown: no "no route" problem is claimed; the pair state still shows.
    expect(out.pairs[0]).toMatchObject({ state: 'primary up, backup idle', healthy: true });
    expect(out.summary.caveats).toEqual(expect.arrayContaining([expect.stringMatching(/static routes could not be read \(rate_limited\)/)]));
  });

  it('truncation: a capped answer is marked in its section and at the top; max_rows leaves tunnels out and says so', async () => {
    const cap = FORTIOS_ENDPOINTS.vpnPhase1.maxItems;
    const many = Array.from({ length: cap + 1 }, (_, i) => phase1(`t${i}`));
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'cmdb/vpn.ipsec/phase1-interface': json(envelope(many)), 'monitor/vpn/ipsec': json(envelope([])) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, max_rows: 5 }));
    expect(out.complete).toBe(false);
    expect(out.truncatedReads).toEqual(['cmdb vpn.ipsec/phase1-interface']);
    expect(out.tunnels).toMatchObject({ truncated: true, truncatedReads: [{ read: 'cmdb vpn.ipsec/phase1-interface', kept: cap, returned: cap + 1 }], total: cap, shown: 5 });
    expect(out.tunnels.moreRows).toBe(`${cap - 5} more not shown; raise max_rows to see them`);
    expect(out.tunnels.tunnels).toHaveLength(5);
    expect(out.summary.sites).toHaveLength(30);
    expect(out.summary.sitesNote).toBe(`${cap - 30} more sites not described; see pairs and tunnels.`);

    // A nested list over the cap (the live phase 2 list of one tunnel).
    const sas = Array.from({ length: MAX_NESTED + 1 }, (_, i) => sa(`p2-${i}`, 'up'));
    const { fn: fn2 } = fakeForticloud(vpnRoutes(SN, { 'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', sas)])) }));
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.tunnels.truncatedReads).toEqual([{ read: 'monitor vpn/ipsec', nestedListsCut: `lists inside a row cut at ${MAX_NESTED} entries` }]);
    expect(out2.truncatedReads).toEqual(['monitor vpn/ipsec']);
    expect(out2.tunnels.tunnels[0]).toMatchObject({ phase2Total: MAX_NESTED + 1, phase2Note: `${MAX_NESTED + 1 - 50} more phase 2 selectors not shown (at most 50 per tunnel)` });
  });

  it('the tunnel filter keeps the named tunnel and the rest of its site; an unknown name lists the tunnels', async () => {
    const reads = {
      'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g', BACKUP), phase1('to-branch')])),
      'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', []), liveTunnel('to-branch', [])])),
    };
    const { fn } = fakeForticloud(vpnRoutes(SN, reads));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, tunnel: 'TO-HQ-4G' }));
    expect(out.filter).toEqual({ tunnel: 'TO-HQ-4G', matched: ['to-hq-fibre', 'to-hq-4g'], note: 'Shows to-hq-4g and the other tunnels to the same site.' });
    expect(out.tunnels.tunnels.map((t: any) => t.name)).toEqual(['to-hq-fibre', 'to-hq-4g']);
    expect(out.summary.sites).toHaveLength(1);
    expect(out.pairs).toHaveLength(1);

    const { fn: fn2 } = fakeForticloud(vpnRoutes(SN, reads));
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN, tunnel: 'nope' }));
    expect(out2.filter.note).toBe('No IPsec tunnel is named nope. Tunnels: to-hq-fibre, to-hq-4g, to-branch.');
    expect(out2.tunnels.tunnels).toEqual([]);
    // A lone tunnel: its own line, no backup.
    const { fn: fn3 } = fakeForticloud(vpnRoutes(SN, reads));
    setFetchForTests(fn3);
    const out3 = dataOf(await call({ serial: SN, tunnel: 'to-branch' }));
    expect(out3.summary.sites).toEqual(['to-branch: down; no backup tunnel. Problems: to-branch is down.']);
  });

  it('SD-WAN member tunnels: no "no route" problem, and a pointer to get_routing', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g')])),
        'cmdb/router/static': json(envelope([{ 'seq-num': 1, dst: '203.0.113.0 255.255.255.0', 'sdwan-zone': [{ name: 'overlay' }], distance: 1, status: 'enable' }])),
        'monitor/virtual-wan/members': json(envelope({ 'to-hq-fibre': { interface: 'to-hq-fibre', status: 'up' }, 'to-hq-4g': { interface: 'to-hq-4g', status: 'up' } })),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.tunnels.tunnels.every((t: any) => t.sdwanMember === true)).toBe(true);
    expect(out.pairs).toEqual([]);
    expect(out.summary.sites).toEqual(["SD-WAN members to-hq-fibre up, to-hq-4g down. Failover between them is SD-WAN's (health checks and SLA): see forticloud_get_routing."]);
  });

  it('two tunnels with routes to the same subnet and no monitor: failover by route distance', async () => {
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g', { dpd: 'disable' })])) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.pairs).toEqual([]);
    expect(out.summary.sites[0]).toMatch(/^to-hq-fibre \/ to-hq-4g: to-hq-fibre up \(DPD on-idle 3x20s\); to-hq-4g down \(DPD off\); no monitor: every tunnel stays up/);
    expect(out.summary.sites[0]).toMatch(/DPD is off on to-hq-4g/);
    expect(out.summary.sites[0]).toMatch(/to-hq-4g is down: the site is reached over to-hq-fibre/);
  });

  it('a dial-up server counts its connected peers; a static tunnel named like an instance stays its own', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('dialup', { type: 'dynamic', 'add-route': 'enable', distance: 15, priority: 0 }), phase1('site'), phase1('site_1')])),
        'cmdb/vpn.ipsec/phase2-interface': json(envelope([])),
        'monitor/vpn/ipsec': json(
          envelope([
            liveTunnel('dialup_0', [sa('dialup', 'up')]),
            liveTunnel('dialup_1', [sa('dialup', 'down')]),
            liveTunnel('site', [sa('site', 'up')]),
            liveTunnel('site_1', [sa('site_1', 'down')]),
          ])
        ),
        'cmdb/router/static': json(envelope([])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const t = Object.fromEntries(out.tunnels.tunnels.map((x: any) => [x.name, x]));
    expect(Object.keys(t)).toEqual(['dialup', 'site', 'site_1']);
    expect(t.dialup).toMatchObject({ type: 'dynamic', status: 'up', statusNote: 'dial-up: 1 peer connected', live: { dialupPeers: 2, dialupPeersUp: 1 }, addRoute: 'enable', routeDistance: 15 });
    expect(t.site).toMatchObject({ status: 'up' });
    expect(t.site_1).toMatchObject({ status: 'down' });
    expect(out.summary.sites).toContain('dialup: up (dial-up: 1 peer connected); no backup tunnel.');
  });

  it('an unreachable device: the phase 1 read fails and nothing else is tried', async () => {
    const { fn, calls } = fakeForticloud(vpnRoutes(SN_DOWN, { 'cmdb/vpn.ipsec/phase1-interface': () => json({ message: 'Device is offline' }, 502) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN_DOWN }));
    expect(fortiosCalls(calls)).toHaveLength(1);
    expect(out.warning).toMatch(/offline/);
    expect(out.tunnels).toMatchObject({ read: 'cmdb vpn.ipsec/phase1-interface', reason: 'failed', liveError: { reason: 'not_tried' } });
    expect(out.bgp).toMatchObject({ reason: 'not_tried' });
    expect(out.sslVpn).toMatchObject({ reason: 'not_tried' });
  });

  it('only GETs the fixed FortiOS paths and passes the VDOM', async () => {
    const { fn, calls } = fakeForticloud(vpnRoutes(SN, {}));
    setFetchForTests(fn);
    await call({ serial: SN, vdom: 'customer1' });
    const fos = fortiosCalls(calls);
    expect(fos).toHaveLength(10);
    expect(fos.every((c) => c.method === 'GET')).toBe(true);
    const allowed = new Set(Object.values(FORTIOS_ENDPOINTS).map((e) => `/forticloudapi/v1/fgt/${SN}/api/v2/${e.path}`));
    expect(fos.every((c) => allowed.has(c.url.pathname))).toBe(true);
    expect(fos.every((c) => c.url.searchParams.get('vdom') === 'customer1')).toBe(true);
  });
});

describe('forticloud_get_vpn: review fixes', () => {
  it('a tunnel missing from a cut live answer has an unknown state, so its pair is not called healthy', async () => {
    const cap = FORTIOS_ENDPOINTS.vpnIpsecLive.maxItems;
    const filler = Array.from({ length: cap }, (_, i) => liveTunnel(`other-${i}`, [sa(`other-${i}`, 'up')]));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, { 'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), ...filler, liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])) })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, tunnel: 'to-hq-4g' }));
    expect(out.truncatedReads).toEqual(['monitor vpn/ipsec']);
    const lte = out.tunnels.tunnels.find((t: any) => t.name === 'to-hq-4g');
    expect(lte.status).toBeUndefined();
    expect(lte.statusNote).toMatch(/the answer was cut/);
    expect(lte.phase2[0].state).toBeUndefined();
    expect(out.pairs[0]).toMatchObject({ state: 'unknown: the live state of to-hq-4g is not known (the live answer was cut)', backupState: 'state unknown' });
    expect(out.pairs[0].healthy).toBeUndefined();
    expect(out.summary.sites[0]).not.toMatch(/Failover should work/);
    expect(out.summary.text).toMatch(/^2 IPsec tunnels \(1 up, 0 partially up, 0 down, 1 unknown\)/);
  });

  it('a shut-down BGP neighbor is listed but does not count as a route over its tunnel', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([])),
        'cmdb/router/bgp': json(
          envelope({
            as: '65001',
            neighbor: [
              { ip: '192.0.2.254', 'remote-as': '65000', interface: 'to-hq-fibre' },
              { ip: '192.0.2.250', 'remote-as': '65000', interface: 'to-hq-4g', shutdown: 'enable' },
            ],
          })
        ),
        'monitor/router/bgp/neighbors': json(envelope([{ neighbor_ip: '192.0.2.254', admin_status: true, state: 'Established' }])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const lte = out.tunnels.tunnels[1];
    expect(lte.bgpNeighbors).toBeUndefined();
    expect(lte.bgpNeighborsShutdown).toEqual(['192.0.2.250']);
    expect(out.bgp.neighbors[1]).toMatchObject({ ip: '192.0.2.250', tunnel: 'to-hq-4g', shutdown: true });
    expect(out.pairs[0]).toMatchObject({ healthy: false, problems: ['backup to-hq-4g has no route using it: it will come up but carry no traffic'] });
    expect(out.summary.sites[0]).toMatch(/192\.0\.2\.250 over to-hq-4g shut down/);

    // Admin down in the live state counts the same.
    const { fn: fn2 } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([])),
        'cmdb/router/bgp': json(envelope({ neighbor: [{ ip: '192.0.2.254', interface: 'to-hq-fibre' }, { ip: '192.0.2.250', interface: 'to-hq-4g' }] })),
        'monitor/router/bgp/neighbors': json(envelope([{ neighbor_ip: '192.0.2.254', admin_status: true, state: 'Established' }, { neighbor_ip: '192.0.2.250', admin_status: false, state: 'Idle' }])),
      })
    );
    setFetchForTests(fn2);
    expect(dataOf(await call({ serial: SN })).tunnels.tunnels[1].bgpNeighborsShutdown).toEqual(['192.0.2.250']);
  });

  it('route-distance failover checks every subnet has a route over another tunnel', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])),
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-4g', 15), route(3, 'to-hq-fibre', 10, '198.51.100.0 255.255.255.0')])),
      })
    );
    setFetchForTests(fn);
    const line = dataOf(await call({ serial: SN })).summary.sites[0];
    expect(line).toMatch(/Problems: 198\.51\.100\.0\/24 has a route only via to-hq-fibre: no other tunnel takes over if it goes down\.$/);
    expect(line).not.toMatch(/should work/);
  });

  it('route-distance failover: a wider route on the other tunnel covers a narrower one', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])),
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-4g', 15), route(3, 'to-hq-fibre', 10, '203.0.113.128 255.255.255.128')])),
      })
    );
    setFetchForTests(fn);
    const line = dataOf(await call({ serial: SN })).summary.sites[0];
    expect(line).not.toMatch(/Problems:/);
    expect(line).toMatch(/should work/);
  });

  it('a BGP neighbor on a /31 tunnel subnet is matched to its tunnel', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([])),
        'cmdb/system/interface': json(envelope([{ name: 'to-hq-fibre', type: 'tunnel', ip: '192.0.2.0 255.255.255.254' }])),
        'cmdb/router/bgp': json(envelope({ as: '65001', 'router-id': '192.0.2.1', neighbor: [{ ip: '192.0.2.1', 'remote-as': '65000' }], 'neighbor-group': [], 'neighbor-range': [] })),
        'monitor/router/bgp/neighbors': notFound(),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.bgp.neighbors[0]).toMatchObject({ ip: '192.0.2.1', tunnel: 'to-hq-fibre' });
    expect(out.tunnels.tunnels.find((t: any) => t.name === 'to-hq-fibre').bgpNeighbors).toEqual(['192.0.2.1']);
  });

  it('a cut live phase 2 list keeps the tunnel state unknown when a configured selector is missing from it', async () => {
    const n = MAX_NESTED + 1;
    const p2s = Array.from({ length: n }, (_, i) => phase2('to-hq-fibre', '203.0.113.0 255.255.255.0', `fibre-${i}`));
    const sas = Array.from({ length: n }, (_, i) => sa(`fibre-${i}`, 'up'));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase2-interface': json(envelope([...p2s, phase2('to-hq-4g')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', sas), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const fibre = out.tunnels.tunnels.find((t: any) => t.name === 'to-hq-fibre');
    expect(fibre.status).toBeUndefined();
    expect(fibre.statusNote).toBe(`state unknown: ${MAX_NESTED} of ${MAX_NESTED} phase 2 selector(s) read are up, 1 not in the part of the live list read (it was cut)`);
    expect(out.pairs[0].healthy).not.toBe(true);
    expect(out.summary.sites[0]).not.toMatch(/Failover should work/);
  });

  it('a cut static route list does not prove a tunnel has no route', async () => {
    const cap = FORTIOS_ENDPOINTS.staticRoutes.maxItems;
    const filler = Array.from({ length: cap }, (_, i) => route(100 + i, 'wan1', 10, `10.${(i >> 8) & 255}.${i & 255}.0 255.255.255.0`));
    const { fn } = fakeForticloud(vpnRoutes(SN, { 'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), ...filler, route(2, 'to-hq-4g', 15)])) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.truncatedReads).toContain('cmdb router/static');
    expect(out.pairs[0].problems ?? []).not.toContainEqual(expect.stringMatching(/has no route using it/));
    expect(out.summary.caveats).toContainEqual(expect.stringMatching(/static route list was cut/));
  });

  it('a cut SD-WAN member list does not prove a tunnel has no route', async () => {
    const cap = FORTIOS_ENDPOINTS.sdwanMembersLive.maxItems;
    const members = Object.fromEntries(Array.from({ length: cap + 1 }, (_, i) => [`port${i}`, { status: 'up' }]));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10)])),
        'monitor/virtual-wan/members': json(envelope(members)),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.truncatedReads).toContain('monitor virtual-wan/members');
    expect(out.pairs[0].problems ?? []).not.toContainEqual(expect.stringMatching(/has no route using it/));
    expect(out.summary.caveats).toContainEqual(expect.stringMatching(/SD-WAN member list was cut/));
  });

  describe('a backup monitoring two primaries', () => {
    const setup = (min: number | undefined, a: 'up' | 'down', b: 'up' | 'down', lte: 'up' | 'down') => {
      const two = { monitor: [{ name: 'to-hq-fibre' }, { name: 'to-hq-nbn' }], ...(min === undefined ? {} : { 'monitor-min': min }) };
      const { fn } = fakeForticloud(
        vpnRoutes(SN, {
          'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-nbn'), phase1('to-hq-4g', two)])),
          'cmdb/vpn.ipsec/phase2-interface': json(envelope([phase2('to-hq-fibre'), phase2('to-hq-nbn'), phase2('to-hq-4g')])),
          'monitor/vpn/ipsec': json(
            envelope([
              liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', a)]),
              liveTunnel('to-hq-nbn', [sa('to-hq-nbn-p2', b)]),
              liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', lte)]),
            ])
          ),
          'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-nbn', 10), route(3, 'to-hq-4g', 15)])),
        })
      );
      setFetchForTests(fn);
    };

    it('monitor-min 0 (all): one primary down, the other up, backup idle is not "both down"', async () => {
      setup(0, 'down', 'up', 'down');
      const out = dataOf(await call({ serial: SN }));
      const fibre = out.pairs.find((p: any) => p.primary === 'to-hq-fibre');
      expect(fibre).toMatchObject({ state: 'primary down, backup idle', backupState: 'idle' });
      expect(fibre.problems).toEqual(['primary to-hq-fibre is down; 1 of 2 monitored primaries are still up, so backup to-hq-4g stays idle (it comes up when all 2 monitored primaries are down)']);
      expect(JSON.stringify(out.pairs)).not.toMatch(/both .* are down|no tunnel to this site/);
      expect(out.pairs.find((p: any) => p.primary === 'to-hq-nbn')).toMatchObject({ state: 'primary up, backup idle', healthy: true });
    });

    it('monitor-min 1: one primary down and the backup up is the expected failover, not an unexpected backup', async () => {
      setup(1, 'down', 'up', 'up');
      const out = dataOf(await call({ serial: SN }));
      expect(out.pairs.find((p: any) => p.primary === 'to-hq-nbn')).toMatchObject({ state: 'primary up, backup up (1 of 2 monitored primaries down)', healthy: true });
      expect(out.pairs.find((p: any) => p.primary === 'to-hq-fibre').problems).toEqual(['primary to-hq-fibre is down: traffic is on the backup']);
      expect(JSON.stringify(out.pairs)).not.toMatch(/is up while/);
    });

    it('monitor-min 1: a primary down and the backup down is flagged', async () => {
      setup(1, 'down', 'up', 'down');
      const out = dataOf(await call({ serial: SN }));
      expect(out.pairs[0].problems).toContain('backup to-hq-4g is down although 1 of 2 monitored primaries are down (it comes up when 1 of 2 monitored primaries are down)');
    });

    it('all primaries up and the backup up is still unexpected', async () => {
      setup(undefined, 'up', 'up', 'up');
      const out = dataOf(await call({ serial: SN }));
      expect(out.pairs[0].problems?.[0]).toMatch(/^backup to-hq-4g is up while only 0 of 2 monitored primaries are down/);
    });
  });

  it('route-distance failover with a tunnel missing from a cut live answer: readiness unknown, not "should work"', async () => {
    const cap = FORTIOS_ENDPOINTS.vpnIpsecLive.maxItems;
    const filler = Array.from({ length: cap }, (_, i) => liveTunnel(`other-${i}`, [sa(`other-${i}`, 'up')]));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), ...filler, liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, tunnel: 'to-hq-4g' }));
    expect(out.truncatedReads).toContain('monitor vpn/ipsec');
    expect(out.summary.sites[0]).not.toMatch(/should work/);
    expect(out.summary.sites[0]).toMatch(/the live state of to-hq-4g is not known, so whether it would take over is not known./);
  });

  it('a monitored primary beyond a cut phase 1 list is unknown, not "not configured"', async () => {
    const cap = FORTIOS_ENDPOINTS.vpnPhase1.maxItems;
    const filler = Array.from({ length: cap - 1 }, (_, i) => phase1(`other-${i}`));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-4g', BACKUP), ...filler, phase1('to-hq-fibre')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'down')])])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, tunnel: 'to-hq-4g' }));
    expect(out.truncatedReads).toContain('cmdb vpn.ipsec/phase1-interface');
    const pair = out.pairs.find((p: any) => p.backup === 'to-hq-4g');
    expect(pair).toMatchObject({ primary: 'to-hq-fibre', backupOnlyWhenPrimaryDown: true, state: 'unknown: to-hq-fibre is not in the part of the phase 1 list read (it was cut)' });
    expect(pair.healthy).toBeUndefined();
    expect(JSON.stringify(pair)).not.toMatch(/not configured/);
  });

  it('a default route on the backup covers the primary subnets', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, { 'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-4g', 15, '0.0.0.0 0.0.0.0')])) })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.pairs[0]).toMatchObject({ state: 'primary up, backup idle', healthy: true });
    expect(out.pairs[0].problems).toBeUndefined();
  });

  it('route-distance failover: a default route on the other tunnel covers a specific subnet', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-4g')])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up')])])),
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-fibre', 10, '0.0.0.0 0.0.0.0'), route(3, 'to-hq-4g', 15, '0.0.0.0 0.0.0.0')])),
      })
    );
    setFetchForTests(fn);
    const line = dataOf(await call({ serial: SN })).summary.sites[0];
    expect(line).not.toMatch(/Problems:/);
  });

  it('a backup whose read selectors are all down but one was cut off is unknown, not idle', async () => {
    const n = MAX_NESTED + 1;
    const p2s = Array.from({ length: n }, (_, i) => phase2('to-hq-4g', '203.0.113.0 255.255.255.0', `lte-${i}`));
    const sas = Array.from({ length: n }, (_, i) => sa(`lte-${i}`, 'down'));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase2-interface': json(envelope([phase2('to-hq-fibre'), ...p2s])),
        'monitor/vpn/ipsec': json(envelope([liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'up')]), liveTunnel('to-hq-4g', sas)])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const lte = out.tunnels.tunnels.find((t: any) => t.name === 'to-hq-4g');
    expect(lte.status).toBeUndefined();
    expect(out.pairs[0].healthy).not.toBe(true);
    expect(out.pairs[0].backupState).not.toBe('idle');
  });

  it('BGP: an exact remote or local address wins over an overlapping subnet on another tunnel', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10)])),
        'cmdb/system/interface': json(
          envelope([
            { name: 'to-hq-fibre', type: 'tunnel', ip: '192.0.2.1 255.255.255.255', 'remote-ip': '192.0.2.2 255.255.255.0' },
            { name: 'to-hq-4g', type: 'tunnel', ip: '192.0.2.3 255.255.255.255', 'remote-ip': '192.0.2.4 255.255.255.0' },
          ])
        ),
        'cmdb/router/bgp': json(envelope({ as: '65001', 'router-id': '192.0.2.1', neighbor: [{ ip: '192.0.2.4', 'remote-as': '65000' }], 'neighbor-group': [], 'neighbor-range': [] })),
        'monitor/router/bgp/neighbors': json(envelope([{ neighbor_ip: '192.0.2.4', local_ip: '192.0.2.3', remote_as: 65000, admin_status: true, state: 'Established', type: 'ipv4' }])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.bgp.neighbors[0]).toMatchObject({ ip: '192.0.2.4', tunnel: 'to-hq-4g' });
    expect(out.pairs[0].problems ?? []).not.toContainEqual(expect.stringMatching(/backup to-hq-4g has no route using it/));
  });

  it('a BGP-only backup whose neighbor was cut from the BGP list is not called unrouted', async () => {
    const others = Array.from({ length: MAX_NESTED }, (_, i) => ({ ip: `198.51.100.${i % 250}`, 'remote-as': '65100', interface: 'wan1' }));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10)])),
        'cmdb/router/bgp': json(envelope({ as: '65001', 'router-id': '192.0.2.1', neighbor: [...others, { ip: '192.0.2.4', 'remote-as': '65000', interface: 'to-hq-4g' }], 'neighbor-group': [], 'neighbor-range': [] })),
        'monitor/router/bgp/neighbors': notFound(),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.truncatedReads).toContain('cmdb router/bgp');
    expect(out.pairs[0].problems ?? []).not.toContainEqual(expect.stringMatching(/has no route using it/));
    expect(out.summary.caveats).toContainEqual(expect.stringMatching(/Not every BGP neighbor could be placed on a tunnel/));
  });

  it('multi-primary failover onto a partly up backup reports the backup selectors that are down', async () => {
    const two = { monitor: [{ name: 'to-hq-fibre' }, { name: 'to-hq-nbn' }], 'monitor-min': 1 };
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/vpn.ipsec/phase1-interface': json(envelope([phase1('to-hq-fibre'), phase1('to-hq-nbn'), phase1('to-hq-4g', two)])),
        'cmdb/vpn.ipsec/phase2-interface': json(envelope([phase2('to-hq-fibre'), phase2('to-hq-nbn'), phase2('to-hq-4g'), phase2('to-hq-4g', '198.51.100.0 255.255.255.0', 'to-hq-4g-voice')])),
        'monitor/vpn/ipsec': json(
          envelope([
            liveTunnel('to-hq-fibre', [sa('to-hq-fibre-p2', 'down')]),
            liveTunnel('to-hq-nbn', [sa('to-hq-nbn-p2', 'up')]),
            liveTunnel('to-hq-4g', [sa('to-hq-4g-p2', 'up'), sa('to-hq-4g-voice', 'down', '198.51.100.0/255.255.255.0')]),
          ])
        ),
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10), route(2, 'to-hq-nbn', 10), route(3, 'to-hq-4g', 15)])),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    for (const p of out.pairs) {
      expect(p.healthy).not.toBe(true);
      expect(p.problems).toContain('backup to-hq-4g is only partly up (1 of 2 phase 2 up)');
    }
  });

  it('a cut phase 2 configuration list keeps an all-up primary unknown', async () => {
    const cap = FORTIOS_ENDPOINTS.vpnPhase2.maxItems;
    const filler = Array.from({ length: cap - 2 }, (_, i) => phase2(`other-${i}`));
    const { fn } = fakeForticloud(
      vpnRoutes(SN, { 'cmdb/vpn.ipsec/phase2-interface': json(envelope([phase2('to-hq-fibre'), phase2('to-hq-4g'), ...filler, phase2('to-hq-fibre', '198.51.100.0 255.255.255.0', 'to-hq-fibre-voice')])) })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, tunnel: 'to-hq-fibre' }));
    expect(out.truncatedReads).toContain('cmdb vpn.ipsec/phase2-interface');
    const fibre = out.tunnels.tunnels.find((t: any) => t.name === 'to-hq-fibre');
    expect(fibre.status).toBeUndefined();
    expect(fibre.statusNote).toMatch(/phase 2 configuration list was cut/);
    expect(out.pairs[0].healthy).not.toBe(true);
    expect(out.summary.sites[0]).not.toMatch(/Failover should work/);
  });

  it('BGP neighbors matched only by address are not called absent when the tunnel addresses cannot be read', async () => {
    const { fn } = fakeForticloud(
      vpnRoutes(SN, {
        'cmdb/router/static': json(envelope([route(1, 'to-hq-fibre', 10)])),
        'cmdb/system/interface': json({ status: 'error', http_status: 403 }, 403),
        'cmdb/router/bgp': json(envelope({ as: '65001', 'router-id': '192.0.2.1', neighbor: [{ ip: '192.0.2.4', 'remote-as': '65000' }], 'neighbor-group': [], 'neighbor-range': [] })),
        'monitor/router/bgp/neighbors': notFound(),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.pairs[0].problems ?? []).not.toContainEqual(expect.stringMatching(/has no route using it/));
    expect(out.summary.caveats).toContainEqual(expect.stringMatching(/Not every BGP neighbor could be placed on a tunnel/));
  });
});
