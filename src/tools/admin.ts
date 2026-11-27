import type { Api } from '../client.js';
import { checkSerial, timeIn } from './format.js';
import { isPrivate, networkCidr, parseFortiosNet, subnetText } from './ip.js';
import type { Net } from './ip.js';
import { checkVdom, cutInfo, deviceInfo } from './network.js';
import { get, notTried } from './routing.js';
import type { Ctx, Got } from './routing.js';
import { clean, compact, num } from './shared.js';
import type { ToolSpec } from './spec.js';

/**
 * forticloud_get_admin_access: how one FortiGate's management access is
 * exposed. Per interface what it allows to the FortiGate itself
 * (allowaccess), the admin ports and lockout settings, the administrators and
 * REST API users with their trusted hosts, the local-in policies and SNMP;
 * then, per WAN-facing interface, whether management is reachable from the
 * internet (yes, restricted, no or unknown) and why.
 *
 * FortiOS reads: 7, plus 1 when a local-in policy names an address object
 * (8 at most). `cmdb system/global` goes first and alone (if the device does
 * not answer, nothing else is tried); then interfaces, admins, API users,
 * local-in policies, SNMP communities and SNMP users at once; then the address
 * objects when needed. Each read reports on its own, as in
 * forticloud_get_routing; after a 429 no further read is started. Passwords,
 * password hashes, API keys, SSH keys, SNMP community strings and SNMP v3 keys
 * are never read off the answer (src/fortios.ts allowlists).
 */

type Raw = Record<string, unknown>;

const text = (v: unknown, max = 120) => clean(v, max);
const list = (v: unknown): Raw[] => (Array.isArray(v) ? (v as Raw[]).filter((x) => !!x && typeof x === 'object') : []);
/** Names from a FortiOS list of {name} (or a plain name, on versions where it is one). */
const names = (v: unknown): string[] =>
  typeof v === 'string' ? v.split(/\s+/).map((x) => text(x, 80)).filter((x): x is string => !!x) : list(v).map((x) => text(x.name, 80)).filter((x): x is string => !!x);
const words = (v: unknown): string[] => (typeof v === 'string' ? v.split(/\s+/).filter(Boolean).map((w) => w.toLowerCase()) : []);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
const firstN = (xs: string[], n: number) => `${xs.slice(0, n).join(', ')}${xs.length > n ? ` and ${xs.length - n} more` : ''}`;

/** The reads this tool makes, by the label each section reports. */
const READ = {
  global: 'cmdb system/global',
  interfaces: 'cmdb system/interface',
  admins: 'cmdb system/admin',
  apiUsers: 'cmdb system/api-user',
  localIn: 'cmdb firewall/local-in-policy',
  snmpCommunities: 'cmdb system.snmp/community',
  snmpUsers: 'cmdb system.snmp/user',
  addresses: 'cmdb firewall/address',
} as const;

/** allowaccess values that open an admin sign-in (GUI or CLI). */
const LOGIN = ['https', 'http', 'ssh', 'telnet'] as const;
type Login = (typeof LOGIN)[number];
const isLogin = (s: string): s is Login => (LOGIN as readonly string[]).includes(s);
/** The FortiOS service object for each sign-in service, and its default port. */
const SERVICE: Record<Login, { name: string; port: number }> = {
  https: { name: 'HTTPS', port: 443 },
  http: { name: 'HTTP', port: 80 },
  ssh: { name: 'SSH', port: 22 },
  telnet: { name: 'TELNET', port: 23 },
};

const whole = (g: Got) => g.ok && !g.res.truncated && !g.res.nestedCut;
const failText = (g: Got) => (g.ok ? 'it was cut' : `${g.fail.reason}${g.httpStatus ? `, HTTP ${g.httpStatus}` : ''}`);

// --- Interfaces --------------------------------------------------------------------------------------

/** A public IPv6 address: not unspecified, link-local, unique local or multicast. */
function publicV6(v: unknown): boolean {
  const s = typeof v === 'string' ? v.trim().toLowerCase().split('/')[0] : '';
  if (!s || s === '::' || /^(fe[89ab]|f[cd]|ff)/.test(s) || s === '::1') return false;
  return s.includes(':');
}

interface Iface {
  name: string;
  alias?: string;
  role?: string;
  type?: string;
  status?: string;
  ip?: string;
  secondaryIps?: string[];
  ipv6?: string;
  /** Sign-in services allowed (IPv4: the primary and secondary addresses). */
  management: Login[];
  ipv6Management?: Login[];
  /** Other allowaccess values (ping, snmp, fgfm, ...). */
  other?: string[];
  wanFacing?: string;
}

function buildInterfaces(rows: Raw[], telnetOff: boolean): Iface[] {
  return rows.map((r) => {
    const v4 = parseFortiosNet(r.ip);
    const sec = list(r.secondaryip);
    const v6 = (r.ipv6 && typeof r.ipv6 === 'object' ? r.ipv6 : {}) as Raw;
    const all4 = [...new Set([...words(r.allowaccess), ...sec.flatMap((s) => words(s.allowaccess))])];
    const all6 = [...new Set(words(v6['ip6-allowaccess']))];
    const login = (ws: string[]) => ws.filter(isLogin).filter((w) => !(w === 'telnet' && telnetOff));
    const secNets = sec.map((s) => parseFortiosNet(s.ip)).filter((n): n is Net => !!n);
    const v6addr = text(v6['ip6-address'], 60);
    const role = text(r.role, 20);
    const wanFacing =
      role === 'wan'
        ? 'role wan'
        : v4 && !isPrivate(v4.ip)
          ? 'public IPv4 address'
          : secNets.some((n) => !isPrivate(n.ip))
            ? 'public secondary IPv4 address'
            : publicV6(v6addr)
              ? 'public IPv6 address'
              : undefined;
    const other = [...new Set([...all4, ...all6].filter((w) => !isLogin(w)))];
    const v6login = login(all6);
    // Which IPv4 address opens which sign-in service (undefined ip: none set, as with DHCP or PPPoE).
    const where = [
      { ip: v4?.ip, services: login(words(r.allowaccess)) },
      ...sec.map((s) => ({ ip: parseFortiosNet(s.ip)?.ip, services: login(words(s.allowaccess)) })),
    ].filter((a) => a.services.length);
    const out = compact({
      name: text(r.name, 40) ?? '',
      alias: text(r.alias, 60),
      role,
      type: text(r.type, 20),
      status: text(r.status, 10),
      ip: v4 ? ipText(v4) : undefined,
      secondaryIps: secNets.length ? secNets.map(ipText) : undefined,
      ipv6: v6addr && v6addr !== '::/0' ? v6addr : undefined,
      management: login(all4),
      ipv6Management: v6login.length ? v6login : undefined,
      other: other.length ? other : undefined,
      wanFacing,
    }) as Iface;
    ADDRESSES.set(out, where);
    return out;
  });
}
/** Per interface, its IPv4 addresses with the sign-in services each allows (kept out of the result). */
const ADDRESSES = new WeakMap<Iface, { ip?: number; services: Login[] }[]>();
const ipText = (n: Net) => {
  const ip = [n.ip >>> 24, (n.ip >>> 16) & 255, (n.ip >>> 8) & 255, n.ip & 255].join('.');
  return `${ip}/${n.prefix}`;
};

// --- Administrators ----------------------------------------------------------------------------------

interface Admin {
  name: string;
  profile?: string;
  vdoms?: string[];
  trustedHosts?: string[];
  anyIpv4Host: boolean;
  ipv6TrustedHosts?: string[];
  anyIpv6Host: boolean;
  twoFactor?: string;
  wildcard?: string;
  remoteGroup?: string;
  apiUser?: true;
}

/** A trusted host, or undefined when it is unset or "any" (0.0.0.0/0). */
function trust4(v: unknown): string | undefined {
  const n = parseFortiosNet(v);
  return n && n.prefix > 0 ? networkCidr(n) : undefined;
}
function trust6(v: unknown): string | undefined {
  const s = typeof v === 'string' ? v.trim() : '';
  return s && !/^::\/0$/.test(s) && !/^::$/.test(s) && !/\/0$/.test(s) ? s.slice(0, 60) : undefined;
}

function adminOf(r: Raw): Admin {
  const t4 = Array.from({ length: 10 }, (_, i) => trust4(r[`trusthost${i + 1}`])).filter((x): x is string => !!x);
  const t6 = Array.from({ length: 10 }, (_, i) => trust6(r[`ip6-trusthost${i + 1}`])).filter((x): x is string => !!x);
  return compact({
    name: text(r.name, 64) ?? '',
    profile: text(r.accprofile, 40),
    vdoms: names(r.vdom).length ? names(r.vdom) : undefined,
    trustedHosts: t4.length ? t4 : undefined,
    anyIpv4Host: t4.length === 0,
    ipv6TrustedHosts: t6.length ? t6 : undefined,
    anyIpv6Host: t6.length === 0,
    twoFactor: text(r['two-factor'], 20),
    wildcard: text(r.wildcard, 10),
    remoteGroup: text(r['remote-group'], 40),
  }) as Admin;
}

function apiUserOf(r: Raw): Admin {
  const th = list(r.trusthost);
  const t4 = th.map((t) => trust4(t['ipv4-trustip'])).filter((x): x is string => !!x);
  const t6 = th.map((t) => trust6(t['ipv6-trustip'])).filter((x): x is string => !!x);
  return compact({
    name: text(r.name, 64) ?? '',
    profile: text(r.accprofile, 40),
    vdoms: names(r.vdom).length ? names(r.vdom) : undefined,
    trustedHosts: t4.length ? t4 : undefined,
    anyIpv4Host: t4.length === 0,
    ipv6TrustedHosts: t6.length ? t6 : undefined,
    anyIpv6Host: t6.length === 0,
    apiUser: true,
  }) as Admin;
}

// --- Local-in policies -------------------------------------------------------------------------------

interface LocalIn {
  id?: number;
  interfaces: string[];
  sources: string[];
  sourceNegate?: true;
  destinations: string[];
  destinationNegate?: true;
  services: string[];
  serviceNegate?: true;
  action?: string;
  schedule?: string;
  status?: string;
  comment?: string;
}

function localInOf(r: Raw): LocalIn {
  return compact({
    id: num(r.policyid),
    interfaces: names(r.intf),
    sources: names(r.srcaddr),
    sourceNegate: r['srcaddr-negate'] === 'enable' ? true : undefined,
    destinations: names(r.dstaddr),
    destinationNegate: r['dstaddr-negate'] === 'enable' ? true : undefined,
    services: names(r.service),
    serviceNegate: r['service-negate'] === 'enable' ? true : undefined,
    action: text(r.action, 10),
    schedule: text(r.schedule, 40),
    status: text(r.status, 10),
    comment: text(r.comments, 200),
  }) as LocalIn;
}

const ANY = new Set(['all', 'any']);
const isAll = (xs: string[]) => xs.some((x) => ANY.has(x.toLowerCase()));

/** An address object as text ("10.0.0.0/24", "a-b", an FQDN), for local-in sources. */
function addressText(r: Raw): string | undefined {
  const type = text(r.type, 20);
  if (type === 'iprange') return `${text(r['start-ip'], 20)}-${text(r['end-ip'], 20)}`;
  if (type === 'fqdn') return text(r.fqdn, 100);
  return r.subnet ? subnetText(r.subnet) : undefined;
}

/**
 * Whether the (IPv4) local-in policies stop sign-ins to this interface from the internet: for every
 * IPv4 address and sign-in service it allows, an enabled, always-on deny on this interface (or any)
 * to that address, from everywhere (or from everywhere except a negated list), with no earlier accept
 * that lets everyone in. Returns the policy ids and who is still let in, or undefined.
 */
function localInLimits(
  iface: Iface,
  policies: LocalIn[],
  addresses: Map<string, { text?: string; net?: Net }> | undefined,
  ports: Record<Login, number | undefined>
): { ids: number[]; allowed: string[] } | undefined {
  const where = ADDRESSES.get(iface) ?? [];
  const live = policies.filter((p) => p.status !== 'disable' && (!p.schedule || p.schedule === 'always'));
  const onIface = (p: LocalIn) => p.interfaces.some((i) => i === iface.name || ANY.has(i.toLowerCase()));
  const inNet = (ip: number, n: Net) => ((ip ^ n.ip) & (n.prefix === 0 ? 0 : (0xffffffff << (32 - n.prefix)) >>> 0)) === 0;
  /** The policy surely applies to this address (all, or an address object that contains it). */
  const surelyTo = (p: LocalIn, ip: number | undefined) =>
    !p.destinationNegate &&
    (isAll(p.destinations) ||
      (ip !== undefined &&
        p.destinations.some((d) => {
          const n = addresses?.get(d)?.net;
          return !!n && inNet(ip, n);
        })));
  /** The policy may apply to this address (anything not shown to miss it). */
  const mayBeTo = (p: LocalIn, ip: number | undefined) =>
    p.destinationNegate ||
    ip === undefined ||
    isAll(p.destinations) ||
    p.destinations.some((d) => {
      const n = addresses?.get(d)?.net;
      return !n || inNet(ip, n);
    });
  const covers = (p: LocalIn, s: Login) =>
    !p.serviceNegate &&
    p.services.some((x) => {
      const u = x.toUpperCase();
      return u === 'ALL' || u === 'ALL_TCP' || (u === SERVICE[s].name && (ports[s] ?? SERVICE[s].port) === SERVICE[s].port);
    });
  /** May match this service (a negated or unknown service object is taken to). */
  const mayCover = (p: LocalIn, s: Login) =>
    p.serviceNegate || p.services.some((x) => !['HTTPS', 'HTTP', 'SSH', 'TELNET'].includes(x.toUpperCase()) || x.toUpperCase() === SERVICE[s].name);
  if (!where.length) return undefined;
  const ids: number[] = [];
  const allowed: string[] = [];
  for (const { ip, services } of where)
    for (const s of services) {
      const idx = live.findIndex((p) => p.action === 'deny' && onIface(p) && surelyTo(p, ip) && covers(p, s) && (p.sourceNegate || isAll(p.sources)));
      if (idx < 0) return undefined;
      const deny = live[idx];
      if (deny.id !== undefined && !ids.includes(deny.id)) ids.push(deny.id);
      if (deny.sourceNegate) allowed.push(...deny.sources);
      for (const p of live.slice(0, idx)) {
        if (p.action !== 'accept' || !onIface(p) || !mayBeTo(p, ip) || !mayCover(p, s)) continue;
        // An earlier accept from everywhere (or everywhere but a few) leaves it open.
        if (p.sourceNegate || isAll(p.sources)) return undefined;
        allowed.push(...p.sources);
      }
    }
  const shown = [...new Set(allowed)].map((a) => {
    const t = addresses?.get(a)?.text;
    return t && t !== a ? `${a} (${t})` : a;
  });
  return { ids, allowed: shown };
}

// --- The verdict -------------------------------------------------------------------------------------

type Verdict = 'yes' | 'restricted' | 'no' | 'unknown';
interface Exposure {
  interface: string;
  alias?: string;
  wanFacing: string;
  services: string[];
  internetManagement: Verdict;
  reason: string;
}

// --- The tool ----------------------------------------------------------------------------------------

async function getAdminAccess(args: Raw, api: Api) {
  const sn = checkSerial(args.serial);
  const vdom = checkVdom(args.vdom);
  const device = await deviceInfo(api, sn);
  const ctx: Ctx = { api, sn, vdom, meta: {}, answered: 0 };

  // system/global goes first, alone: if the device does not answer at all, nothing else is tried.
  const globalGot = await get(ctx, 'adminGlobal', READ.global);
  if (!globalGot.ok && globalGot.fail.reason === 'rate_limited') throw ctx.rateLimit!;
  const down = !globalGot.ok && globalGot.deviceDown;
  const skip = (read: string) => notTried(read, `not tried: the ${READ.global} read failed, so the device is probably not reachable through FortiGate Cloud`);
  const [ifGot, adminGot, apiGot, localGot, commGot, userGot] = down
    ? [READ.interfaces, READ.admins, READ.apiUsers, READ.localIn, READ.snmpCommunities, READ.snmpUsers].map(skip)
    : await Promise.all([
        get(ctx, 'adminInterfaces', READ.interfaces),
        get(ctx, 'admins', READ.admins),
        get(ctx, 'apiUsers', READ.apiUsers),
        get(ctx, 'localIn', READ.localIn),
        get(ctx, 'snmpCommunities', READ.snmpCommunities),
        get(ctx, 'snmpUsers', READ.snmpUsers),
      ]);
  if (ctx.answered === 0 && ctx.rateLimit) throw ctx.rateLimit;

  const policies = localGot.ok ? localGot.res.rows.map(localInOf) : [];
  // Address objects only when a local-in policy names one (8th read).
  const named = policies.some((p) => [...p.sources, ...p.destinations].some((a) => !ANY.has(a.toLowerCase())));
  const addrGot: Got | undefined = named && !down ? await get(ctx, 'addresses', READ.addresses) : undefined;
  const addresses = addrGot?.ok
    ? new Map(addrGot.res.rows.map((r) => [String(r.name ?? ''), { text: addressText(r), net: r.type === undefined || r.type === 'ipmask' ? parseFortiosNet(r.subnet) : undefined }]))
    : undefined;

  // Settings.
  const g = globalGot.ok ? (globalGot.res.rows[0] ?? {}) : undefined;
  const ports: Record<Login, number | undefined> = {
    https: num(g?.['admin-sport']),
    http: num(g?.['admin-port']),
    ssh: num(g?.['admin-ssh-port']),
    telnet: num(g?.['admin-telnet-port']),
  };
  const telnetOff = g?.['admin-telnet'] === 'disable';
  const settings = g
    ? compact({
        httpsPort: ports.https,
        httpPort: ports.http,
        sshPort: ports.ssh,
        telnet: text(g['admin-telnet'], 10),
        telnetPort: ports.telnet,
        httpsRedirect: text(g['admin-https-redirect'], 10),
        idleTimeoutMinutes: num(g.admintimeout),
        lockoutThreshold: num(g['admin-lockout-threshold']),
        lockoutDurationSeconds: num(g['admin-lockout-duration']),
        maintainerAccount: text(g['admin-maintainer'], 10),
      })
    : undefined;

  const ifaces = ifGot.ok ? buildInterfaces(ifGot.res.rows, telnetOff) : [];
  const admins = adminGot.ok ? adminGot.res.rows.map(adminOf) : [];
  const apiUsers = apiGot.ok ? apiGot.res.rows.map(apiUserOf) : [];

  // Per WAN-facing interface: is a sign-in reachable from the internet?
  const exposures: Exposure[] = [];
  for (const i of ifaces.filter((x) => x.wanFacing)) {
    const v4 = i.management;
    const v6 = i.ipv6Management ?? [];
    const services = [...new Set([...v4, ...v6])];
    const portOf = (s: Login) => (ports[s] && ports[s] !== SERVICE[s].port ? `${s} (port ${ports[s]})` : s);
    const base = { interface: i.name, alias: i.alias, wanFacing: i.wanFacing!, services: services.map(portOf) };
    const say = (internetManagement: Verdict, reason: string) => exposures.push(compact({ ...base, internetManagement, reason }) as Exposure);
    if (!services.length) {
      say('no', `no admin sign-in service (https, http, ssh, telnet) in allowaccess${i.other?.length ? `; allows ${i.other.join(', ')}` : ''}`);
      continue;
    }
    const svcText = services.map(portOf).join(', ');
    // An (IPv4) local-in deny from everywhere limits IPv4 whatever the admins are. IPv6 local-in
    // policies are not read, so IPv6 sign-ins are judged by the trusted hosts alone.
    const localKnown = localGot.ok && whole(localGot) && (!named || !!addrGot?.ok);
    const limit = v4.length && localKnown ? localInLimits(i, policies, addresses, ports) : undefined;
    const limitText = limit
      ? `local-in polic${limit.ids.length === 1 ? 'y' : 'ies'} ${limit.ids.join(', ') || '(no id)'} den${limit.ids.length === 1 ? 'ies' : 'y'} IPv4 sign-ins from everywhere${limit.allowed.length ? ` except ${firstN(limit.allowed, 10)}` : ''}`
      : undefined;
    if (limit && !v6.length) {
      say('restricted', `${svcText} allowed, but ${limitText}`);
      continue;
    }
    const open4 = limit ? [] : v4;
    const pre = limitText ? `${limitText}; on IPv6 ` : '';
    // Who could sign in: admins for every service, REST API users for https/http.
    const isWeb = (s: Login) => s === 'https' || s === 'http';
    const web = open4.some(isWeb) || v6.some(isWeb);
    const adminsKnown = whole(adminGot);
    const apiKnown = !web || whole(apiGot);
    const open = (a: Admin) => (open4.length && a.anyIpv4Host) || (v6.length && a.anyIpv6Host);
    const openAdmins = adminsKnown ? admins.filter(open) : [];
    const openApi = web && apiKnown ? apiUsers.filter((a) => (open4.some(isWeb) && a.anyIpv4Host) || (v6.some(isWeb) && a.anyIpv6Host)) : [];
    if (openAdmins.length || openApi.length) {
      const who = [...openAdmins.map((a) => a.name), ...openApi.map((a) => `${a.name} (REST API)`)];
      // Open on IPv4 needs the local-in policies read to say "yes".
      const viaV4 = open4.length > 0 && [...openAdmins, ...openApi].some((a) => a.anyIpv4Host);
      const viaV6Only = !viaV4;
      if (viaV4 && !localKnown) {
        say('unknown', `${svcText} allowed and ${firstN(who, 5)} ha${who.length === 1 ? 's' : 've'} no trusted host, but the local-in policies could not be checked (${localGot.ok ? (whole(localGot) ? `${READ.addresses}: ${addrGot ? failText(addrGot) : 'not read'}` : 'the list was cut') : failText(localGot)})`);
      } else {
        say(
          'yes',
          `${svcText} allowed; ${pre}${firstN(who, 5)} ha${who.length === 1 ? 's' : 've'} no trusted host${viaV6Only ? ' (IPv6; IPv6 local-in policies are not read)' : ', and no local-in policy denies it'}`
        );
      }
      continue;
    }
    if (!adminsKnown || !apiKnown) {
      const missing = [!adminsKnown ? `${READ.admins} (${failText(adminGot)})` : undefined, !apiKnown ? `${READ.apiUsers} (${failText(apiGot)})` : undefined].filter(Boolean);
      say('unknown', `${svcText} allowed; ${pre}the trusted hosts could not be checked: ${missing.join(' and ')} could not be read in full`);
      continue;
    }
    const hosts = [...new Set([...admins, ...(web ? apiUsers : [])].flatMap((a) => [...(open4.length ? (a.trustedHosts ?? []) : []), ...(v6.length ? (a.ipv6TrustedHosts ?? []) : [])]))];
    say(
      'restricted',
      admins.length + (web ? apiUsers.length : 0) === 0
        ? `${svcText} allowed, but ${pre}there are no administrators`
        : `${svcText} allowed, but ${pre}every administrator${web && apiUsers.length ? ' and REST API user' : ''} has trusted hosts: ${firstN(hosts, 10)}`
    );
  }

  // SNMP.
  const communities = commGot.ok
    ? commGot.res.rows.map((r) => {
        const hosts = list(r.hosts).map((h) => compact({ ip: subnetText(h.ip), interface: text(h.interface, 40), type: text(h['host-type'], 10) }));
        const hosts6 = list(r.hosts6).map((h) => compact({ ip: text(h.ipv6, 60), interface: text(h.interface, 40), type: text(h['host-type'], 10) }));
        const query = r['query-v1-status'] !== 'disable' || r['query-v2c-status'] !== 'disable';
        const anyHost = hosts.length === 0 || hosts.some((h) => !h.ip || h.ip === '0.0.0.0/0');
        return compact({
          id: num(r.id),
          status: text(r.status, 10),
          queryV1: text(r['query-v1-status'], 10),
          queryV2c: text(r['query-v2c-status'], 10),
          trapV1: text(r['trap-v1-status'], 10),
          trapV2c: text(r['trap-v2c-status'], 10),
          hosts: hosts.length ? hosts : undefined,
          hosts6: hosts6.length ? hosts6 : undefined,
          pollableFromAnyHost: r.status !== 'disable' && query && anyHost ? true : undefined,
        });
      })
    : undefined;
  const snmpUsers = userGot.ok
    ? userGot.res.rows.map((r) =>
        compact({
          name: text(r.name, 40),
          status: text(r.status, 10),
          securityLevel: text(r['security-level'], 20),
          queries: text(r.queries, 10),
          queryPort: num(r['query-port']),
          trapStatus: text(r['trap-status'], 10),
          notifyHosts: text(r['notify-hosts'], 300),
          notifyHosts6: text(r['notify-hosts6'], 300),
        })
      )
    : undefined;

  const reads = [globalGot, ifGot, adminGot, apiGot, localGot, commGot, userGot, ...(addrGot ? [addrGot] : [])];
  const unread = reads.filter((x): x is Extract<Got, { ok: false }> => !x.ok);
  const truncated = reads.filter((x) => x.ok && (x.res.truncated || x.res.nestedCut)).map((x) => x.read);
  const sectionError = (x: Got) => (x.ok ? undefined : compact({ ...x.fail, httpStatus: x.httpStatus, note: 'unavailable' }));

  const caveats: string[] = [];
  if (!ifGot.ok) caveats.push(`The interfaces could not be read (${failText(ifGot)}), so which interfaces allow management is not known.`);
  else if (!whole(ifGot)) caveats.push('The interface list was cut, so interfaces past the cut are not judged.');
  if (!globalGot.ok) caveats.push(`The admin settings could not be read (${failText(globalGot)}): the ports are taken as the defaults and telnet as allowed where allowaccess has it.`);
  if (communities?.some((c) => c.pollableFromAnyHost) && ifaces.some((i) => i.wanFacing && (i.other ?? []).includes('snmp')))
    caveats.push('A WAN-facing interface allows snmp and an SNMP community with queries on has no host restriction.');
  if (ifaces.some((i) => i.wanFacing && (i.other ?? []).includes('fgfm'))) caveats.push('fgfm (FortiManager and FortiGate Cloud management) is allowed on a WAN-facing interface; it is not an admin sign-in.');
  caveats.push('IPv6 local-in policies (local-in-policy6) are not read; an IPv6 verdict does not take them into account.');

  const counts = (v: Verdict) => exposures.filter((e) => e.internetManagement === v).length;
  const summaryText = ifGot.ok
    ? `${plural(exposures.length, 'WAN-facing interface')}: ${counts('yes')} reachable from the internet, ${counts('restricted')} restricted, ${counts('no')} without admin sign-in, ${counts('unknown')} unknown. ${plural(admins.length, 'administrator')}${adminGot.ok ? '' : ' (not read)'}, ${plural(apiUsers.length, 'REST API user')}${apiGot.ok ? '' : ' (not read)'}, ${plural(policies.length, 'local-in policy').replace('policys', 'policies')}${localGot.ok ? '' : ' (not read)'}.`
    : `Management exposure unknown: ${READ.interfaces} could not be read (${failText(ifGot)}).`;

  return compact({
    device: compact({ serial: sn, name: device.row.name, account: device.row.account, model: device.row.model, firmware: device.row.firmware, fortigateCloudConnection: device.row.connection }),
    fortios: compact({ version: ctx.meta.version, build: ctx.meta.build, vdom: ctx.meta.vdom ?? vdom }),
    readAt: timeIn(Date.now()),
    note: device.note,
    warning:
      device.row.connection === 'offline'
        ? 'FortiGate Cloud shows this device offline (management tunnel down); the FortiOS reads go through that tunnel and may fail.'
        : undefined,
    complete: unread.length || truncated.length ? false : undefined,
    unreadable: unread.length ? unread.map((x) => compact({ read: x.fail.read, reason: x.fail.reason, httpStatus: x.httpStatus, retryAfterSeconds: x.fail.retryAfterSeconds })) : undefined,
    truncatedReads: truncated.length ? truncated : undefined,
    rateLimited: ctx.rateLimit
      ? {
          retryAfterSeconds: ctx.rateLimit.retryAfterSeconds,
          note: `FortiCloud rate-limited a read, so no further reads were made; the reads marked rate_limited are missing. Try again in ${ctx.rateLimit.retryAfterSeconds} s for them.`,
        }
      : undefined,
    summary: compact({
      text: summaryText,
      internetManagement: exposures,
      caveats,
      note: 'internetManagement: yes = an admin sign-in service (https, http, ssh, telnet) is allowed on a WAN-facing interface, at least one administrator (or REST API user, for https/http) has no trusted host, and no local-in policy denies it; restricted = every administrator has trusted hosts, or a local-in deny from everywhere covers every allowed sign-in service; no = no sign-in service on that interface; unknown = a read needed for the answer failed or was cut.',
    }),
    adminSettings: settings ?? sectionError(globalGot),
    interfaces: ifGot.ok
      ? compact({
          source: READ.interfaces,
          total: ifGot.res.rows.length,
          note: 'Only interfaces that allow anything to the FortiGate itself, or that face the internet (role wan or a public address), are listed. management: the sign-in services allowed (IPv4, primary and secondary addresses); ipv6Management: the same on IPv6.',
          ...cutInfo([[ifGot.read, ifGot.res]]),
          interfaces: ifaces.filter((i) => i.management.length || i.ipv6Management || i.other || i.wanFacing),
        })
      : sectionError(ifGot),
    administrators: adminGot.ok
      ? compact({
          source: READ.admins,
          total: admins.length,
          noTrustedHost: admins.filter((a) => a.anyIpv4Host).map((a) => a.name),
          ...cutInfo([[adminGot.read, adminGot.res]]),
          admins,
        })
      : sectionError(adminGot),
    apiUsers: apiGot.ok
      ? compact({ source: READ.apiUsers, total: apiUsers.length, noTrustedHost: apiUsers.filter((a) => a.anyIpv4Host).map((a) => a.name), ...cutInfo([[apiGot.read, apiGot.res]]), users: apiUsers })
      : sectionError(apiGot),
    localInPolicies: localGot.ok
      ? compact({
          source: READ.localIn,
          total: policies.length,
          addressesError: addrGot && !addrGot.ok ? sectionError(addrGot) : undefined,
          ...cutInfo([[localGot.read, localGot.res], ...(addrGot?.ok ? [[addrGot.read, addrGot.res] as [string, typeof addrGot.res]] : [])]),
          policies: policies.map((p) =>
            compact({
              ...p,
              sources: p.sources.map((a) => {
                const t = addresses?.get(a)?.text;
                return t && t !== a ? `${a} (${t})` : a;
              }),
            })
          ),
        })
      : sectionError(localGot),
    snmp: compact({
      communities: communities ? compact({ source: READ.snmpCommunities, note: 'The community name is the community string, so it is never shown; communities are listed by id.', total: communities.length, communities }) : sectionError(commGot),
      users: snmpUsers ? { source: READ.snmpUsers, total: snmpUsers.length, users: snmpUsers } : sectionError(userGot),
    }),
  });
}

export const ADMIN_SPECS: ToolSpec[] = [
  {
    name: 'forticloud_get_admin_access',
    description:
      "How one FortiGate's management access is exposed, read live from the device through FortiGate Cloud (read-only FortiOS API). summary.internetManagement: per WAN-facing interface (role wan or a public address), whether an admin sign-in is reachable from the internet: yes (https/http/ssh/telnet allowed, an administrator with no trusted host, and no local-in deny), restricted (every administrator has trusted hosts, or a local-in policy denies it from everywhere; the allowed sources are named), no (no sign-in service allowed) or unknown (a read it depends on failed or was cut), with the reason. Also: interfaces with their allowaccess split into sign-in services and others (ping, snmp, fgfm...), the admin settings (HTTPS/HTTP/SSH ports, telnet, HTTPS redirect, idle timeout, lockout, maintainer account), administrators and REST API users (profile, trusted hosts IPv4 and IPv6, two-factor, wildcard, remote group), local-in policies with address names resolved, and SNMP (communities by id with their hosts and query/trap switches; v3 user names and security level). Each read reports on its own when it is not supported, denied (with the HTTP status), rate limited or truncated. Never returns passwords, password hashes, API keys, SSH keys, SNMP community strings or SNMP v3 keys.",
    params: {
      serial: { type: 'string', description: 'The FortiGate serial number, e.g. FGT60FTK00000000.', required: true, maxLength: 40 },
      vdom: { type: 'string', description: 'The VDOM, on a FortiGate with VDOMs (default: the root VDOM).', maxLength: 31 },
    },
    run: getAdminAccess,
  },
];
