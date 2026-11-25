import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setFetchForTests } from '../client.js';
import { FORTIOS_ENDPOINTS, MAX_NESTED, filterFortios } from '../fortios.js';
import { clearCaches } from '../tools/format.js';
import { ALL_TOOLS, dispatchToolCall } from '../tools/index.js';
import { clearNetworkCaches } from '../tools/network.js';
import { isLegacySdwan } from '../tools/routing.js';
import { FGT, dataOf, fakeForticloud, json, textOf } from './test-helpers.js';
import type { Call, Route } from './test-helpers.js';

const SN = 'FGT60FTK00000011';
const SN_OLD = 'FGT60ETK00000012';
const SN_DOWN = 'FGT40FTK00000013';
const DEVICES = [
  { sn: SN, name: 'example-fw', model: 'FortiGate 60F', firmwareVersion: '7.4.4', tunnelAlive: true, subAccountOid: 100 },
  { sn: SN_OLD, name: 'example-old-fw', model: 'FortiGate 60E', firmwareVersion: '6.2.15', tunnelAlive: true, subAccountOid: 100 },
  { sn: SN_DOWN, name: 'example-down-fw', model: 'FortiGate 40F', firmwareVersion: '7.2.8', tunnelAlive: false, subAccountOid: 100 },
];
const SUBACCOUNTS = [{ oid: 100, name: 'Example Client' }];

/** Secret-looking fields FortiOS might add to any of these objects; none may come back. */
const SECRETS = { password: 'SECRET-twamp-1', psksecret: 'SECRET-psk-2', 'private-key': 'SECRET-key-3', token: 'SECRET-token-4' };

const envelope = (results: unknown, version = 'v7.4.4') => ({
  http_method: 'GET',
  results,
  vdom: 'root',
  status: 'success',
  http_status: 200,
  serial: SN,
  version,
  build: 2662,
});
const FOS = (sn: string, path: string) => `${FGT}/fgt/${sn}/api/v2/${path}`;
const notFound = () => json({ status: 'error', http_status: 404 }, 404);

const LINKS_UP = {
  wan1: { name: 'wan1', ip: '198.51.100.2', mask: 30, link: true },
  wan2: { name: 'wan2', ip: '203.0.113.2', mask: 30, link: true },
  internal: { name: 'internal', ip: '203.0.113.129', mask: 25, link: true },
};
const DISABLED_SDWAN ={ status: 'disable', zone: [{ name: 'virtual-wan-link' }], members: [], 'health-check': [], service: [] };

/** A FortiGate with two WANs; each scenario overrides the reads that differ. */
function routingRoutes(sn: string, reads: Record<string, Route | Response>, version = 'v7.4.4') {
  const base: Record<string, Route | Response> = {
    [`${FGT}/devices`]: json(DEVICES),
    [`${FGT}/subaccounts`]: json(SUBACCOUNTS),
    [FOS(sn, 'cmdb/router/policy')]: json(envelope([], version)),
    [FOS(sn, 'cmdb/system/link-monitor')]: json(envelope([], version)),
    [FOS(sn, 'monitor/system/link-monitor')]: json(envelope({}, version)),
    [FOS(sn, 'cmdb/system/sdwan')]: json(envelope(DISABLED_SDWAN, version)),
    [FOS(sn, 'monitor/virtual-wan/health-check')]: json(envelope({}, version)),
    [FOS(sn, 'monitor/virtual-wan/members')]: json(envelope({}, version)),
    [FOS(sn, 'monitor/system/interface')]: json(envelope(LINKS_UP, version)),
    [FOS(sn, 'monitor/vpn/ipsec')]: json(envelope([], version)),
  };
  const out: Record<string, Route | Response> = { ...base };
  for (const [path, r] of Object.entries(reads)) out[FOS(sn, path)] = r;
  return out;
}

const liveDefault = (iface: string, gateway: string, distance: number, priority: number) => ({
  ip_version: 4,
  type: 'static',
  ip_mask: '0.0.0.0/0',
  gateway,
  interface: iface,
  distance,
  priority,
  metric: 0,
});
const connected = { ip_version: 4, type: 'connect', ip_mask: '203.0.113.128/25', gateway: '0.0.0.0', interface: 'internal', distance: 0, metric: 0 };

const call = (args: Record<string, unknown>) => dispatchToolCall('forticloud_get_routing', args);
const fortiosCalls = (calls: Call[]) => calls.filter((c) => c.url.pathname.includes('/fgt/'));

beforeEach(() => {
  process.env.FORTICLOUD_API_ID = 'APIUSER0000000000000';
  process.env.FORTICLOUD_API_PASSWORD = 'Sup3r-Secret-Passw0rd!';
  for (const k of ['FORTICLOUD_AUTH_URL', 'FORTICLOUD_ASSET_URL', 'FORTICLOUD_FGT_URL', 'FORTICLOUD_UNTRUSTED_MARKERS', 'FORTICLOUD_TIME_ZONE']) delete process.env[k];
  clearCaches();
  clearNetworkCaches();
});
afterEach(() => setFetchForTests(undefined));

// --- Scenarios -------------------------------------------------------------------------------------

const SDWAN_ON = {
  'cmdb/router/static': json(envelope([{ 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', gateway: '0.0.0.0', device: '', 'sdwan-zone': [{ name: 'virtual-wan-link' }], distance: 1, priority: 1, status: 'enable', ...SECRETS }])),
  'cmdb/system/sdwan': json(
    envelope({
      status: 'enable',
      'load-balance-mode': 'source-ip-based',
      zone: [{ name: 'virtual-wan-link' }],
      members: [
        { 'seq-num': 1, interface: 'wan1', zone: 'virtual-wan-link', gateway: '198.51.100.1', priority: 1, cost: 0, weight: 1, status: 'enable', ...SECRETS },
        { 'seq-num': 2, interface: 'wan2', zone: 'virtual-wan-link', gateway: '203.0.113.1', priority: 1, cost: 0, weight: 1, status: 'enable' },
      ],
      'health-check': [
        {
          name: 'internet',
          server: '192.0.2.53 192.0.2.54',
          protocol: 'ping',
          interval: 500,
          failtime: 5,
          recoverytime: 5,
          members: [{ 'seq-num': 1 }, { 'seq-num': 2 }],
          sla: [{ id: 1, 'latency-threshold': 250, 'jitter-threshold': 50, 'packetloss-threshold': 5 }],
          'update-static-route': 'enable',
          password: 'SECRET-twamp-hc',
          user: 'twamp-user',
        },
      ],
      service: [
        {
          id: 1,
          name: 'voice-via-wan1',
          mode: 'sla',
          dst: [{ name: 'voip-provider' }],
          src: [{ name: 'all' }],
          'priority-members': [{ 'seq-num': 1 }, { 'seq-num': 2 }],
          'priority-zone': [],
          'health-check': [{ name: 'internet' }],
          sla: [{ 'health-check': 'internet', id: 1 }],
        },
      ],
    })
  ),
  'monitor/virtual-wan/health-check': json(
    envelope({
      internet: {
        wan1: { status: 'up', latency: 4.21, jitter: 0.3, packet_loss: 0, sla_targets_met: [1], state_changed: 1764000000, session: 12, password: 'SECRET-live' },
        wan2: { status: 'down', latency: 0, jitter: 0, packet_loss: 100, sla_targets_met: [], state_changed: 1764003600 },
      },
    })
  ),
  'monitor/virtual-wan/members': json(
    envelope({
      wan1: { interface: 'wan1', link: 'up', status: 'up', session: 120, tx_bandwidth: 1000, rx_bandwidth: 2000 },
      wan2: { interface: 'wan2', link: 'up', status: 'down', session: 0 },
    })
  ),
  'monitor/router/ipv4': json(envelope([connected, liveDefault('wan1', '198.51.100.1', 1, 1)])),
};

const LINK_MONITOR = {
  'cmdb/router/static': json(
    envelope([
      { 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', gateway: '198.51.100.1', device: 'wan1', distance: 10, priority: 1, weight: 0, status: 'enable', comment: 'Primary fibre' },
      { 'seq-num': 2, dst: '0.0.0.0 0.0.0.0', gateway: '203.0.113.1', device: 'wan2', distance: 20, priority: 1, weight: 0, status: 'enable', comment: 'Backup 4G' },
      { 'seq-num': 3, dst: '198.51.100.128 255.255.255.128', blackhole: 'enable', distance: 254, status: 'enable' },
    ])
  ),
  'cmdb/system/link-monitor': json(
    envelope([
      {
        name: 'lm-wan1',
        srcintf: 'wan1',
        server: [{ address: '192.0.2.53' }, { address: '192.0.2.54' }],
        protocol: 'ping',
        'gateway-ip': '198.51.100.1',
        interval: 500,
        failtime: 5,
        recoverytime: 5,
        'update-static-route': 'enable',
        'update-cascade-interface': 'enable',
        status: 'enable',
        ...SECRETS,
      },
      { name: 'lm-wan2', srcintf: 'wan2', server: [{ address: '192.0.2.53' }], protocol: 'ping', 'update-static-route': 'enable', status: 'enable' },
    ])
  ),
  'monitor/system/link-monitor': json(
    envelope({
      'lm-wan1': { wan1: { status: 'dead', latency: 0, jitter: 0, packet_loss: 100, state_changed: 1764000000 } },
      'lm-wan2': { wan2: { status: 'alive', latency: 31.5, jitter: 2.1, packet_loss: 0, token: 'SECRET-live-token' } },
    })
  ),
  'monitor/router/ipv4': json(envelope([connected, liveDefault('wan2', '203.0.113.1', 20, 1)])),
};

const STATIC_ONLY = {
  'cmdb/router/static': json(
    envelope([
      { 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', gateway: '198.51.100.1', device: 'wan1', distance: 10, priority: 1, status: 'enable' },
      { 'seq-num': 2, dst: '0.0.0.0 0.0.0.0', gateway: '203.0.113.1', device: 'wan2', distance: 10, priority: 5, status: 'enable' },
    ])
  ),
  'cmdb/router/policy': json(
    envelope([
      {
        'seq-num': 1,
        'input-device': [{ name: 'internal' }],
        src: [{ subnet: '203.0.113.128 255.255.255.128' }],
        dst: [{ subnet: '0.0.0.0 0.0.0.0' }],
        dstaddr: [{ name: 'voip-provider' }],
        protocol: 6,
        'start-port': 5060,
        'end-port': 5060,
        gateway: '203.0.113.1',
        'output-device': 'wan2',
        status: 'enable',
        comments: 'SIP via wan2',
        ...SECRETS,
      },
    ])
  ),
  'monitor/router/ipv4': json(envelope([connected, liveDefault('wan1', '198.51.100.1', 10, 1), liveDefault('wan2', '203.0.113.1', 10, 5)])),
};

describe('forticloud_get_routing', () => {
  it('is listed as a read-only tool with serial, max_rows and vdom', () => {
    const tool = ALL_TOOLS.find((t) => t.name === 'forticloud_get_routing')!;
    expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    expect(Object.keys(tool.inputSchema.properties ?? {})).toEqual(['serial', 'max_rows', 'vdom']);
    expect(tool.inputSchema.required).toEqual(['serial']);
  });

  it('SD-WAN on: members, health checks with live state per member, rules, and the summary', async () => {
    const { fn } = fakeForticloud(routingRoutes(SN, SDWAN_ON));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).not.toContain('SECRET');
    expect(textOf(res)).not.toContain('twamp-user');
    const out = dataOf(res);
    expect(out.device).toMatchObject({ serial: SN, name: 'example-fw', account: 'Example Client' });
    expect(out.fortios).toEqual({ version: 'v7.4.4', build: 2662, vdom: 'root' });
    expect(out.complete).toBeUndefined();
    expect(out.summary.failover).toBe('sdwan');
    expect(out.summary.text).toMatch(/^SD-WAN \(enabled\) with 2 members \(wan1, wan2\) and 1 health check \(internet -> 192\.0\.2\.53 192\.0\.2\.54 ping on wan1, wan2\)/);
    expect(out.summary.text).toMatch(/The default route uses SD-WAN: SD-WAN zone virtual-wan-link/);
    expect(out.summary.activeDefaultRoute).toBe('wan1 via 198.51.100.1 (distance 1, priority 1)');
    // The SD-WAN default route, one path per member.
    expect(out.summary.defaultRoutes).toEqual([
      expect.objectContaining({ source: 'sdwan', seq: 1, interface: 'wan1', gateway: '198.51.100.1', sdwanZone: 'virtual-wan-link', inRoutingTable: true, state: 'active' }),
      expect.objectContaining({ source: 'sdwan', seq: 1, interface: 'wan2', inRoutingTable: false, state: 'inactive', reason: 'SD-WAN health check internet reports wan2 down' }),
    ]);
    expect(out.summary.paths).toEqual(['Internet (0.0.0.0/0): wan1 active (distance 1); wan2 (distance 1) is down: SD-WAN health check internet reports wan2 down.']);
    const s = out.sdwan;
    expect(s.source).toEqual({ configured: 'cmdb system/sdwan', healthChecks: 'monitor virtual-wan/health-check', members: 'monitor virtual-wan/members' });
    expect(s.status).toBe('enable');
    expect(s.zones).toEqual(['virtual-wan-link']);
    expect(s.members[0]).toMatchObject({ seq: 1, interface: 'wan1', gateway: '198.51.100.1', priority: 1, weight: 1, status: 'enable', live: { link: 'up', state: 'up', sessions: 120 } });
    expect(s.members[1].live).toMatchObject({ state: 'down' });
    const hc = s.healthChecks[0];
    expect(hc).toMatchObject({ name: 'internet', protocol: 'ping', members: ['wan1', 'wan2'], updateStaticRoute: 'enable' });
    expect(hc.sla).toEqual([{ id: 1, latencyThresholdMs: 250, jitterThresholdMs: 50, packetLossThresholdPercent: 5 }]);
    expect(hc.live).toEqual([
      expect.objectContaining({ interface: 'wan1', state: 'up', latencyMs: 4.21, jitterMs: 0.3, packetLossPercent: 0, slaTargetsMet: [1] }),
      expect.objectContaining({ interface: 'wan2', state: 'down', packetLossPercent: 100, slaTargetsMet: [] }),
    ]);
    expect(hc.live[0].stateChanged).toMatch(/^\d{4}-\d\d-\d\d /);
    expect(s.rules[0]).toEqual({
      id: 1,
      name: 'voice-via-wan1',
      mode: 'sla',
      source: ['all'],
      destination: ['voip-provider'],
      priorityMembers: ['wan1', 'wan2'],
      healthChecks: ['internet'],
      sla: [{ healthCheck: 'internet', id: 1 }],
    });
    expect(out.staticRoutes.routes[0]).toMatchObject({ seq: 1, destination: '0.0.0.0/0', viaSdwan: true, sdwanZones: ['virtual-wan-link'] });
    expect(out.linkMonitors).toMatchObject({ total: 0, monitors: [] });
    expect(out.policyRoutes).toMatchObject({ total: 0, routes: [] });
  });

  it('static routes plus link-monitor: monitors with live state, the active and standby default routes', async () => {
    const { fn } = fakeForticloud(routingRoutes(SN, LINK_MONITOR));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(textOf(res)).not.toContain('SECRET');
    const out = dataOf(res);
    expect(out.summary.failover).toBe('static-routes-with-link-monitor');
    expect(out.summary.text).toMatch(/^Static routes with link-monitor \(update-static-route enabled on wan1 \(lm-wan1 -> 192\.0\.2\.53, 192\.0\.2\.54, ping\), wan2 \(lm-wan2 -> 192\.0\.2\.53, ping\)\)/);
    expect(out.summary.activeDefaultRoute).toBe('wan2 via 203.0.113.1 (distance 20, priority 1)');
    const [wan1, wan2] = out.summary.defaultRoutes;
    expect(wan1).toMatchObject({ interface: 'wan1', distance: 10, monitoredBy: ['lm-wan1'], inRoutingTable: false, state: 'inactive', reason: 'link-monitor lm-wan1 reports wan1 dead' });
    expect(wan2).toMatchObject({ interface: 'wan2', distance: 20, monitoredBy: ['lm-wan2'], inRoutingTable: true, state: 'active' });
    expect(out.summary.paths[0]).toBe('Internet (0.0.0.0/0): wan2 active (distance 20); wan1 (distance 10, preferred) is down: link-monitor lm-wan1 reports wan1 dead.');
    expect(out.summary.defaultRoutes).toHaveLength(2); // the blackhole route is not a default route

    const lm = out.linkMonitors;
    expect(lm.source).toEqual({ configured: 'cmdb system/link-monitor', live: 'monitor system/link-monitor' });
    expect(lm.monitors[0]).toMatchObject({
      name: 'lm-wan1',
      interface: 'wan1',
      servers: ['192.0.2.53', '192.0.2.54'],
      protocol: 'ping',
      gatewayIp: '198.51.100.1',
      interval: 500,
      failtime: 5,
      recoverytime: 5,
      updateStaticRoute: 'enable',
      updateCascadeInterface: 'enable',
      status: 'enable',
      live: [expect.objectContaining({ interface: 'wan1', state: 'dead', packetLossPercent: 100 })],
    });
    expect(lm.monitors[1].live).toEqual([{ interface: 'wan2', state: 'alive', latencyMs: 31.5, jitterMs: 2.1, packetLossPercent: 0 }]);
    expect(out.staticRoutes.routes[0]).toEqual({
      seq: 1,
      destination: '0.0.0.0/0',
      gateway: '198.51.100.1',
      interface: 'wan1',
      distance: 10,
      priority: 1,
      weight: 0,
      status: 'enable',
      comment: 'Primary fibre',
    });
    expect(out.staticRoutes.routes[2]).toMatchObject({ destination: '198.51.100.128/25', blackhole: true });
    expect(out.staticRoutes.defaultRoutes).toBe(2);
    expect(out.sdwan).toMatchObject({ status: 'disable' });
  });

  it('static routes only: distance and priority, no health check; the lower priority one is active', async () => {
    const { fn } = fakeForticloud(routingRoutes(SN, STATIC_ONLY));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(textOf(res)).not.toContain('SECRET');
    const out = dataOf(res);
    expect(out.summary.failover).toBe('static-routes-distance-priority');
    expect(out.summary.text).toMatch(/^Static routes by distance\/priority only, no health check/);
    expect(out.summary.text).not.toMatch(/only one default route/);
    expect(out.summary.activeDefaultRoute).toBe('wan1 via 198.51.100.1 (distance 10, priority 1)');
    expect(out.summary.defaultRoutes.map((r: any) => [r.interface, r.state])).toEqual([
      ['wan1', 'active'],
      ['wan2', 'standby'],
    ]);
    expect(out.policyRoutes.routes).toEqual([
      {
        seq: 1,
        status: 'enable',
        inputDevices: ['internal'],
        source: ['203.0.113.128/25'],
        destination: ['voip-provider'],
        protocol: 6,
        ports: '5060',
        gateway: '203.0.113.1',
        outputDevice: 'wan2',
        comment: 'SIP via wan2',
      },
    ]);

    // One default route learned on the interface (DHCP), none configured.
    const { fn: fn2 } = fakeForticloud(
      routingRoutes(SN, { 'cmdb/router/static': json(envelope([])), 'monitor/router/ipv4': json(envelope([connected, { ...liveDefault('wan1', '198.51.100.1', 5, 0), type: 'dhcp' }])) })
    );
    setFetchForTests(fn2);
    const one = dataOf(await call({ serial: SN })).summary;
    expect(one.failover).toBe('static-routes-distance-priority');
    expect(one.text).toMatch(/learned on the interface \(DHCP or PPPoE\)/);
    expect(one.text).toMatch(/only one default route, so there is no failover/);
    expect(one.defaultRoutes[0]).toMatchObject({ interface: 'wan1', source: 'other', liveType: 'dhcp', configured: false, state: 'active' });
  });

  it('FortiOS 6.2: SD-WAN is read from system/virtual-wan-link, without trying system/sdwan first', async () => {
    const v = 'v6.2.15';
    const { fn, calls } = fakeForticloud(
      routingRoutes(
        SN_OLD,
        {
          'cmdb/router/static': json(envelope([{ 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', device: 'virtual-wan-link', 'virtual-wan-link': 'enable', distance: 1, priority: 0, status: 'enable' }], v)),
          'cmdb/system/virtual-wan-link': json(
            envelope(
              {
                status: 'enable',
                members: [
                  { 'seq-num': 1, interface: 'wan1', gateway: '198.51.100.1', status: 'enable' },
                  { 'seq-num': 2, interface: 'wan2', gateway: '203.0.113.1', status: 'enable' },
                ],
                'health-check': [{ name: 'ping-dns', server: '192.0.2.53', protocol: 'ping', members: [{ 'seq-num': 0 }], 'update-static-route': 'enable' }],
                service: [{ id: 1, name: 'web', mode: 'priority', 'health-check': 'ping-dns', 'priority-members': [{ 'seq-num': 2 }] }],
              },
              v
            )
          ),
          'monitor/virtual-wan/health-check': json(envelope({ 'ping-dns': { wan1: { status: 'up', latency: 9, jitter: 1, packet_loss: 0 }, wan2: { status: 'up', latency: 20, jitter: 2, packet_loss: 1 } } }, v)),
          'monitor/virtual-wan/members': notFound,
          'monitor/router/ipv4': json(envelope([liveDefault('wan1', '198.51.100.1', 1, 0), liveDefault('wan2', '203.0.113.1', 1, 0)], v)),
        },
        v
      )
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN_OLD }));
    expect(fortiosCalls(calls).some((c) => c.url.pathname.endsWith('cmdb/system/sdwan'))).toBe(false);
    expect(out.sdwan.source.configured).toBe('cmdb system/virtual-wan-link (FortiOS 6.2 and older)');
    expect(out.sdwan.healthChecks[0]).toMatchObject({ name: 'ping-dns', members: ['all members'], live: [expect.objectContaining({ interface: 'wan1', state: 'up' }), expect.objectContaining({ interface: 'wan2' })] });
    expect(out.sdwan.rules[0]).toMatchObject({ name: 'web', mode: 'priority', healthChecks: ['ping-dns'], priorityMembers: ['wan2'] });
    expect(out.sdwan.membersLiveError).toMatchObject({ read: 'monitor virtual-wan/members', reason: 'not_supported' });
    expect(out.summary.failover).toBe('sdwan');
    expect(out.summary.text).toMatch(/^SD-WAN \(enabled\) with 2 members \(wan1, wan2\) and 1 health check \(ping-dns -> 192\.0\.2\.53 ping on all members\)/);
    expect(out.summary.activeDefaultRoute).toBe('wan1 via 198.51.100.1 (distance 1, priority 0); wan2 via 203.0.113.1 (distance 1, priority 0)');
    expect(out.staticRoutes.routes[0]).toMatchObject({ interface: 'virtual-wan-link', viaSdwan: true });
    expect(out.unreadable).toEqual([{ read: 'monitor virtual-wan/members', reason: 'not_supported' }]);
    expect(isLegacySdwan('v6.2.15')).toBe(true);
    expect(isLegacySdwan('v6.4.0')).toBe(false);
    expect(isLegacySdwan('v7.0.12')).toBe(false);
    expect(isLegacySdwan(undefined)).toBe(false);
  });

  it('falls back to system/virtual-wan-link when system/sdwan is not there (version not known)', async () => {
    const { fn, calls } = fakeForticloud(
      routingRoutes(SN, {
        'cmdb/router/static': notFound,
        'cmdb/system/sdwan': notFound,
        'cmdb/system/virtual-wan-link': json(envelope({ status: 'disable', members: [] }, 'v6.0.18')),
        'monitor/router/ipv4': json(envelope([liveDefault('wan1', '198.51.100.1', 10, 0)], 'v6.0.18')),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const order = fortiosCalls(calls).map((c) => c.url.pathname.split('/api/v2/')[1]);
    expect(order.indexOf('cmdb/system/sdwan')).toBeLessThan(order.indexOf('cmdb/system/virtual-wan-link'));
    expect(out.sdwan.source.configured).toBe('cmdb system/virtual-wan-link (FortiOS 6.2 and older)');
    expect(out.sdwan.configuredError).toBeUndefined();
    expect(out.staticRoutes).toMatchObject({ read: 'cmdb router/static', reason: 'not_supported' });
    // No link-monitor, SD-WAN off: the live table's one default route.
    expect(out.summary.failover).toBe('static-routes-distance-priority');
    expect(out.summary.caveats).toEqual(expect.arrayContaining([expect.stringMatching(/static routes could not be read \(not_supported\)/)]));
  });

  it('sections fail independently: each says why, and the rest still show', async () => {
    const { fn } = fakeForticloud(
      routingRoutes(SN, {
        ...STATIC_ONLY,
        'cmdb/router/policy': notFound,
        'cmdb/system/link-monitor': json({ status: 'error', http_status: 403, message: 'permission denied' }),
        'monitor/system/link-monitor': json(envelope({ 'lm-wan1': { wan1: { status: 'alive', latency: 5, jitter: 1, packet_loss: 0 } } })),
        'cmdb/system/sdwan': notFound,
        'cmdb/system/virtual-wan-link': notFound,
        'monitor/virtual-wan/health-check': () => json({ message: 'internal error' }, 500),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(out.complete).toBe(false);
    expect(out.policyRoutes).toMatchObject({ read: 'cmdb router/policy', reason: 'not_supported' });
    expect(out.policyRoutes.error).toMatch(/404/);
    expect(out.linkMonitors.configuredError).toMatchObject({ read: 'cmdb system/link-monitor', reason: 'permission_denied' });
    expect(out.linkMonitors.monitors).toEqual([{ name: 'lm-wan1', live: [{ interface: 'wan1', state: 'alive', latencyMs: 5, jitterMs: 1, packetLossPercent: 0 }] }]);
    expect(out.sdwan.configuredError).toMatchObject({ read: 'cmdb system/sdwan and cmdb system/virtual-wan-link', reason: 'not_supported' });
    expect(out.sdwan.healthCheckLiveError).toMatchObject({ reason: 'failed' });
    expect(out.sdwan.source).toEqual({ members: 'monitor virtual-wan/members' });
    expect(out.staticRoutes.total).toBe(2);
    expect(out.summary.activeDefaultRoute).toBe('wan1 via 198.51.100.1 (distance 10, priority 1)');
    // SD-WAN is not there, but without the link-monitor settings static failover cannot be named.
    expect(out.summary.failover).toBe('unknown');
    expect(out.summary.text).toMatch(/link-monitor settings could not be read \(permission_denied\)/);
    expect(out.unreadable.map((u: any) => [u.read, u.reason])).toEqual([
      ['cmdb router/policy', 'not_supported'],
      ['cmdb system/link-monitor', 'permission_denied'],
      ['cmdb system/sdwan and cmdb system/virtual-wan-link', 'not_supported'],
      ['monitor virtual-wan/health-check', 'failed'],
    ]);

    // SD-WAN settings refused: SD-WAN cannot be ruled out.
    const { fn: fn2 } = fakeForticloud(routingRoutes(SN, { ...STATIC_ONLY, 'cmdb/system/sdwan': json({ status: 'error', http_status: 403 }) }));
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.summary).toMatchObject({ failover: 'unknown' });
    expect(out2.summary.text).toMatch(/SD-WAN settings could not be read \(permission_denied\)/);
    expect(out2.sdwan.configuredError).toMatchObject({ read: 'cmdb system/sdwan', reason: 'permission_denied' });

    // The live table unreadable: the method is still known, the active route is not.
    const { fn: fn3 } = fakeForticloud(routingRoutes(SN, { ...LINK_MONITOR, 'monitor/router/ipv4': () => json({}, 502) }));
    setFetchForTests(fn3);
    const out3 = dataOf(await call({ serial: SN }));
    expect(out3.summary.failover).toBe('static-routes-with-link-monitor');
    expect(out3.summary.activeDefaultRoute).toBeUndefined();
    expect(out3.summary.defaultRoutes[0].inRoutingTable).toBeUndefined();
    expect(out3.summary.caveats).toEqual([expect.stringMatching(/live routing table could not be read \(failed\)/)]);
  });

  it('an unreachable device: the static route read fails and nothing else is tried', async () => {
    const { fn, calls } = fakeForticloud(routingRoutes(SN_DOWN, { 'cmdb/router/static': () => json({ message: 'Device is offline' }, 502) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN_DOWN }));
    expect(fortiosCalls(calls)).toHaveLength(1);
    expect(out.warning).toMatch(/offline/);
    expect(out.staticRoutes).toMatchObject({ reason: 'failed' });
    expect(out.policyRoutes).toMatchObject({ reason: 'not_tried' });
    expect(out.linkMonitors.configuredError).toMatchObject({ reason: 'not_tried' });
    expect(out.sdwan.configuredError).toMatchObject({ reason: 'not_tried' });
    expect(out.summary.failover).toBe('unknown');
  });

  it('only GETs the fixed FortiOS paths and passes the VDOM', async () => {
    const { fn, calls } = fakeForticloud(routingRoutes(SN, SDWAN_ON));
    setFetchForTests(fn);
    await call({ serial: SN, vdom: 'customer1' });
    const fos = fortiosCalls(calls);
    expect(fos).toHaveLength(10);
    expect(fos.every((c) => c.method === 'GET')).toBe(true);
    const allowed = new Set(Object.values(FORTIOS_ENDPOINTS).map((e) => `/forticloudapi/v1/fgt/${SN}/api/v2/${e.path}`));
    expect(fos.every((c) => allowed.has(c.url.pathname))).toBe(true);
    expect(fos.every((c) => c.url.searchParams.get('vdom') === 'customer1')).toBe(true);
    const bad = await call({ serial: SN, vdom: 'root/../x' });
    expect(bad.structuredContent).toMatchObject({ error_type: 'invalid_input' });
  });

  it('truncation: a capped answer is marked in its section and at the top; max_rows leaves rows out and says so', async () => {
    const cap = FORTIOS_ENDPOINTS.staticRoutes.maxItems;
    const many = Array.from({ length: cap + 1 }, (_, i) => ({ 'seq-num': i + 1, dst: `10.${i >> 8}.${i & 255}.0 255.255.255.0`, device: 'internal', status: 'enable' }));
    const liveCap = FORTIOS_ENDPOINTS.routesLive.maxItems;
    const liveMany = Array.from({ length: liveCap + 1 }, (_, i) => ({ ip_mask: `10.${i >> 8}.${i & 255}.0/24`, type: 'static', interface: 'internal' }));
    const { fn } = fakeForticloud(routingRoutes(SN, { 'cmdb/router/static': json(envelope(many)), 'monitor/router/ipv4': json(envelope(liveMany)) }));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN, max_rows: 5 }));
    expect(out.complete).toBe(false);
    expect(out.truncatedReads).toEqual(['cmdb router/static', 'monitor router/ipv4']);
    expect(out.staticRoutes).toMatchObject({ truncated: true, truncatedReads: [{ read: 'cmdb router/static', kept: cap, returned: cap + 1 }], total: cap, shown: 5 });
    expect(out.staticRoutes.moreRows).toBe(`${cap - 5} more not shown; raise max_rows to see them`);
    expect(out.staticRoutes.routes).toHaveLength(5);
    expect(out.summary.caveats).toEqual(expect.arrayContaining([expect.stringMatching(/live routing table was longer than this server reads/)]));

    // A nested list over the cap (SD-WAN health-check members).
    const members = Array.from({ length: MAX_NESTED + 1 }, (_, i) => ({ 'seq-num': i + 1 }));
    const { fn: fn2 } = fakeForticloud(routingRoutes(SN, { ...SDWAN_ON, 'cmdb/system/sdwan': json(envelope({ status: 'enable', members: [{ 'seq-num': 1, interface: 'wan1' }], 'health-check': [{ name: 'hc', members }] })) }));
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.sdwan.truncatedReads).toEqual([{ read: 'cmdb system/sdwan', nestedListsCut: `lists inside a row cut at ${MAX_NESTED} entries` }]);
    expect(out2.truncatedReads).toEqual(['cmdb system/sdwan']);
  });

  it('a 429 on the first read is the structured rate_limited error; a later one marks only the reads it stopped', async () => {
    const { fn, calls } = fakeForticloud(routingRoutes(SN, { ...SDWAN_ON, 'cmdb/router/static': json({}, 429, { 'Retry-After': '120' }) }));
    setFetchForTests(fn);
    const res = await call({ serial: SN });
    expect(res.isError).toBe(true);
    expect(res.structuredContent).toEqual({ error_type: 'rate_limited', retry_after_seconds: 120 });
    expect(fortiosCalls(calls)).toHaveLength(1);

    const { fn: fn2 } = fakeForticloud(routingRoutes(SN, { ...SDWAN_ON, 'monitor/virtual-wan/health-check': json({}, 429, { 'Retry-After': '90' }) }));
    setFetchForTests(fn2);
    const res2 = await call({ serial: SN });
    expect(res2.isError).toBeFalsy();
    const out = dataOf(res2);
    expect(out.complete).toBe(false);
    expect(out.rateLimited).toMatchObject({ retryAfterSeconds: 90 });
    expect(out.rateLimited.note).toMatch(/Try again in 90 s/);
    expect(out.sdwan.healthCheckLiveError).toMatchObject({ read: 'monitor virtual-wan/health-check', reason: 'rate_limited', retryAfterSeconds: 90 });
    expect(out.unreadable).toEqual(expect.arrayContaining([{ read: 'monitor virtual-wan/health-check', reason: 'rate_limited', retryAfterSeconds: 90 }]));
    expect(out.staticRoutes.total).toBe(1);
  });

  it('a read started after a 429 is not sent', async () => {
    // The live table answers 429 before the SD-WAN fallback would be read.
    const { fn, calls } = fakeForticloud(
      routingRoutes(SN, {
        'cmdb/router/static': json(envelope([])),
        'cmdb/system/sdwan': async () => {
          await new Promise((r) => setTimeout(r, 30));
          return notFound();
        },
        'monitor/router/ipv4': json({}, 429, { 'Retry-After': '60' }),
      })
    );
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    expect(fortiosCalls(calls).some((c) => c.url.pathname.endsWith('cmdb/system/virtual-wan-link'))).toBe(false);
    expect(out.sdwan.configuredError).toMatchObject({ reason: 'rate_limited' });
    expect(out.sdwan.configuredError.error).toMatch(/not asked/);
  });
});

describe('FortiOS answer shapes for routing', () => {
  it('a settings object is one row; a name -> interface map is one row per pair; a scalar list is kept', () => {
    const one = filterFortios(envelope({ status: 'enable', members: [{ 'seq-num': 1, interface: 'wan1', password: 'SECRET-x' }] }), FORTIOS_ENDPOINTS.sdwanConfig);
    expect(one.rows).toEqual([{ status: 'enable', members: [{ 'seq-num': 1, interface: 'wan1' }] }]);
    const nested = filterFortios(
      envelope({ hc: { wan1: { status: 'up', sla_targets_met: [1, 2, { x: 1 }], key: 'SECRET-y' }, wan2: { status: 'down' } }, flat: { status: 'alive', interface: 'wan3' } }),
      FORTIOS_ENDPOINTS.sdwanHealthLive
    );
    expect(nested.rows).toEqual([
      { name: 'hc', interface: 'wan1', status: 'up', sla_targets_met: [1, 2] },
      { name: 'hc', interface: 'wan2', status: 'down' },
      { name: 'flat', interface: 'wan3', status: 'alive' },
    ]);
    // A plain name where 7.x has a list (an SD-WAN rule's health check on 6.2) is kept.
    const legacy = filterFortios(envelope({ service: [{ name: 'r', 'health-check': 'hc' }] }), FORTIOS_ENDPOINTS.sdwanLegacy);
    expect(legacy.rows[0].service).toEqual([{ name: 'r', 'health-check': 'hc' }]);
  });
});

describe('routeCandidates: every path per destination, like the routing-table database', () => {
  // Two static default routes at distance 1 (the wan1 one is out: its link-monitor is dead), a
  // distance-5 backup via wan1, a remote subnet over two tunnels (the preferred one down),
  // connected routes and a disabled route.
  const DATABASE = {
    'cmdb/router/static': json(
      envelope([
        { 'seq-num': 1, dst: '0.0.0.0 0.0.0.0', gateway: '192.0.2.1', device: 'wan1', distance: 1, priority: 0, status: 'enable' },
        { 'seq-num': 2, dst: '0.0.0.0 0.0.0.0', gateway: '198.51.100.1', device: 'wan2', distance: 1, priority: 0, status: 'enable' },
        { 'seq-num': 3, dst: '0.0.0.0 0.0.0.0', gateway: '192.0.2.9', device: 'wan1', distance: 5, priority: 0, status: 'enable', comment: 'backup' },
        { 'seq-num': 4, dst: '203.0.113.0 255.255.255.128', device: 'tunnel-a', distance: 15, status: 'enable' },
        { 'seq-num': 5, dst: '203.0.113.0 255.255.255.128', device: 'tunnel-b', distance: 10, status: 'enable' },
        { 'seq-num': 6, dst: '198.51.100.64 255.255.255.192', gateway: '198.51.100.1', device: 'wan2', distance: 10, status: 'disable' },
      ])
    ),
    'cmdb/system/link-monitor': json(
      envelope([{ name: 'lm-wan1', srcintf: 'wan1', 'gateway-ip': '192.0.2.1', server: [{ address: '192.0.2.53' }], protocol: 'ping', 'update-static-route': 'enable', status: 'enable' }])
    ),
    'monitor/system/link-monitor': json(envelope({ 'lm-wan1': { wan1: { status: 'dead', latency: 0, jitter: 0, packet_loss: 100 } } })),
    'monitor/vpn/ipsec': json(
      envelope([
        { name: 'tunnel-a', rgwy: '192.0.2.200', proxyid: [{ p2name: 'tunnel-a', status: 'up' }] },
        { name: 'tunnel-b', rgwy: '198.51.100.200', proxyid: [{ p2name: 'tunnel-b', status: 'down' }] },
      ])
    ),
    'monitor/router/ipv4': json(
      envelope([
        { type: 'connect', ip_mask: '192.0.2.0/28', gateway: '0.0.0.0', interface: 'wan1', distance: 0 },
        { type: 'connect', ip_mask: '198.51.100.0/30', gateway: '0.0.0.0', interface: 'wan2', distance: 0 },
        { type: 'connect', ip_mask: '203.0.113.128/25', gateway: '0.0.0.0', interface: 'internal', distance: 0 },
        liveDefault('wan2', '198.51.100.1', 1, 0),
        { type: 'static', ip_mask: '203.0.113.0/25', gateway: '0.0.0.0', interface: 'tunnel-a', distance: 15, priority: 0 },
      ])
    ),
  };

  it('lists active, standby and inactive paths with the reason, sorted by destination then distance', async () => {
    const { fn } = fakeForticloud(routingRoutes(SN, DATABASE));
    setFetchForTests(fn);
    const out = dataOf(await call({ serial: SN }));
    const rc = out.routeCandidates;
    expect(rc.source).toMatch(/^derived: cmdb router\/static .* monitor router\/ipv4; FortiOS has no documented REST read of the routing-table database$/);
    expect(rc.stateFrom).toEqual(['monitor system/link-monitor', 'monitor virtual-wan/health-check', 'monitor system/interface', 'monitor vpn/ipsec']);
    const rows = rc.routes.map((r: any) => [r.destination, r.interface, r.gateway, r.distance, r.source, r.state, r.reason]);
    expect(rows).toEqual([
      ['0.0.0.0/0', 'wan1', '192.0.2.1', 1, 'static', 'inactive', 'link-monitor lm-wan1 reports wan1 dead'],
      ['0.0.0.0/0', 'wan2', '198.51.100.1', 1, 'static', 'active', undefined],
      ['0.0.0.0/0', 'wan1', '192.0.2.9', 5, 'static', 'standby', 'wan2 wins with a lower distance'],
      ['192.0.2.0/28', 'wan1', undefined, 0, 'connected', 'active', undefined],
      ['198.51.100.0/30', 'wan2', undefined, 0, 'connected', 'active', undefined],
      ['198.51.100.64/26', 'wan2', '198.51.100.1', 10, 'static', 'inactive', 'disabled in config'],
      ['203.0.113.0/25', 'tunnel-b', undefined, 10, 'static', 'inactive', 'tunnel tunnel-b is down'],
      ['203.0.113.0/25', 'tunnel-a', undefined, 15, 'static', 'active', undefined],
      ['203.0.113.128/25', 'internal', undefined, 0, 'connected', 'active', undefined],
    ]);
    expect(rc.routes[0]).toMatchObject({ seq: 1, configured: true, inRoutingTable: false, monitoredBy: ['lm-wan1'] });
    expect(rc.routes[3]).toMatchObject({ configured: false, liveType: 'connect', inRoutingTable: true });
    expect(rc.total).toBe(9);

    expect(out.summary.failover).toBe('static-routes-with-link-monitor');
    expect(out.summary.paths).toEqual([
      'Internet (0.0.0.0/0): wan2 active (distance 1); wan1 via 192.0.2.1 (distance 1) is down: link-monitor lm-wan1 reports wan1 dead; backup wan1 via 192.0.2.9 at distance 5.',
      '198.51.100.64/26: no path in use; wan2 (distance 10) is down: disabled in config.',
      '203.0.113.0/25: tunnel-a active (distance 15); tunnel-b (distance 10, preferred) is down: tunnel tunnel-b is down.',
    ]);
    expect(out.summary.activeDefaultRoute).toBe('wan2 via 198.51.100.1 (distance 1, priority 0)');
    expect(out.summary.defaultRoutes.map((r: any) => r.state)).toEqual(['inactive', 'active', 'standby']);
  });

  it('an interface whose link is down is the reason; without the live table no route has a state', async () => {
    const { fn } = fakeForticloud(
      routingRoutes(SN, {
        ...DATABASE,
        'monitor/system/link-monitor': json(envelope({})),
        'monitor/system/interface': json(envelope({ ...LINKS_UP, wan1: { name: 'wan1', link: false } })),
      })
    );
    setFetchForTests(fn);
    const rc = dataOf(await call({ serial: SN })).routeCandidates;
    expect(rc.routes[0]).toMatchObject({ interface: 'wan1', distance: 1, state: 'inactive', reason: 'interface wan1 link is down' });

    const { fn: fn2 } = fakeForticloud(routingRoutes(SN, { ...DATABASE, 'monitor/router/ipv4': () => json({}, 502) }));
    setFetchForTests(fn2);
    const out2 = dataOf(await call({ serial: SN }));
    expect(out2.routeCandidates.source).toMatch(/^configured routes only/);
    expect(out2.routeCandidates.routes.every((r: any) => r.state === undefined)).toBe(true);
    expect(out2.routeCandidates.total).toBe(6);
    expect(out2.summary.paths[0]).toMatch(/^Internet \(0\.0\.0\.0\/0\): .*which is in use is not known/);
  });

  it('a candidate list longer than max_rows says how many are left out; a failed tunnel read is reported', async () => {
    const { fn } = fakeForticloud(routingRoutes(SN, { ...DATABASE, 'monitor/vpn/ipsec': notFound }));
    setFetchForTests(fn);
    const rc = dataOf(await call({ serial: SN, max_rows: 3 })).routeCandidates;
    expect(rc).toMatchObject({ total: 9, shown: 3, moreRows: '6 more not shown; raise max_rows to see them' });
    expect(rc.ipsecLiveError).toMatchObject({ read: 'monitor vpn/ipsec', reason: 'not_supported' });
  });
});
