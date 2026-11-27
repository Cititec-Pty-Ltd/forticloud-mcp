# FortiCloud MCP server

A read-only MCP server for [Fortinet FortiCloud](https://support.fortinet.com). Claude can ask which FortiGates are offline in FortiGate Cloud, what firmware they run, how their config backups are set, what a FortiGate's interfaces, DHCP, routes, VIPs and VPNs look like, how it fails over between WANs (SD-WAN, static routes with link-monitor, or distance and priority alone), whether its IPsec VPN failover is set up right and would take over, which client an IP address belongs to, and, from Asset Management, which support and FortiGuard entitlements expire soon.

It uses the same framework as Cititec's other MCP servers: TypeScript, `@modelcontextprotocol/sdk`, a stdio transport, vitest tests, tsup and a Docker image.

## The APIs

One FortiCloud **IAM API user** reaches two portals, each with its own OAuth token:

| Portal | API | Token `client_id` |
|---|---|---|
| **FortiGate Cloud** (being renamed FortiManagement Cloud) | `GET https://api.fortigate.forticloud.com/forticloudapi/v1/...` (`/devices`, `/devices/{sn}`, `/devices/{sn}/configbackups/setting`, `/subaccounts`) | `fortigatecloud` |
| **FortiOS on each FortiGate**, through FortiGate Cloud | `GET https://api.fortigate.forticloud.com/forticloudapi/v1/fgt/{sn}/api/v2/...` (a fixed list of FortiOS `cmdb` and `monitor` reads; see "Network tools", "Routing tool", "VPN tool" and "Admin access tool") | `fortigatecloud` |
| **Asset Management** v3 | `POST https://support.fortinet.com/ES/api/registration/v3/...` with a JSON query (`products/list`, `products/details`, `contracts/list`, `folders/list`) | `assetmanagement` |

- **Tokens:** `POST https://customerapiauth.fortinet.com/api/v1/oauth/token/` (the trailing slash matters) with `{username: <API ID>, password, client_id, grant_type: "password"}`. The token is cached for its `expires_in` less two minutes. A token that FortiCloud rejects early (HTTP 401) is replaced once.
- **Failed sign-ins:** FortiCloud answers bad credentials with HTTP 400 `invalid_grant`. Repeated failures are reported to lock the API user out of every portal for 15 to 30 minutes, so after a refusal this server does not try to sign in again for 10 minutes.
- **Regions:** FortiGate Cloud has Global (which is also Canada), US, Europe and Japan hosts (`api.`, `usapi.`, `euapi.`, `jpapi.fortigate.forticloud.com`). The API only shows the region you call. The token and Asset Management hosts are global.
- **Read-only:** every Asset Management call this server can make is one of its read endpoints (a fixed list in `src/client.ts`), and FortiGate Cloud is only called with GET. The FortiOS proxy is called only with GET and only for the endpoints named in `src/fortios.ts`; no tool takes a path. The other Asset Management v3 endpoints (register, decommission, transfer, folders/create...) are not reachable. Give the API user a **read-only** permission profile anyway.

### What is not confirmed yet

Fortinet's full API reference (FNDN) needs a login. The endpoints and fields above come from Fortinet's public docs and KB articles and from open-source clients. These are handled defensively and need a live check:

- the token lifetime (14,400 s, 3,660 s and 3,600 s are all reported); the server uses whatever `expires_in` says;
- FortiGate Cloud `/devices` paging (`limit` and `offset`): the server stops on a short page, on a page with nothing new, or at the `total` the items carry;
- a "last seen" time on a device: the public sample has none, so `lastSeen` is filled from any of several likely field names, and `forticloud_get_device` shows every other field the API returns (`otherFields`);
- a list of config backup revisions: only the automatic backup settings (`configbackups/setting`) are documented;
- `/subaccounts` (account names), Asset Management's page size (25) and `totalPages`, and the fields `folderPath` and `status` on list items;
- the FortiOS paths other than `cmdb/system/interface` and `monitor/system/interface` (confirmed through the proxy): they follow the FortiOS 7.0-7.6 REST API reference, as do `include_vlan` and `include_aggregate` on `monitor/system/interface`. The routing reads also need a live check: the answer shapes of `monitor/system/link-monitor` and `monitor/virtual-wan/health-check` (taken as name, then interface, then the counters, and read either way), `monitor/virtual-wan/members` (6.4 and later) and `cmdb/system/virtual-wan-link` on 6.2. The VPN reads too: the phase 2 selector field names on `monitor/vpn/ipsec` (`proxy_src`/`proxy_dst` in the reference, `proxysrc`/`proxydst` as `forticloud_get_network` reads them; `forticloud_get_vpn` keeps both), what `creation_time` counts, the `monitor` field of `phase1-interface` (a name on 6.4, a list on 7.x; read either way), `status` on `cmdb/vpn.ssl/settings` (7.4 and later), and any uptime or prefix count on `monitor/router/bgp/neighbors` (not in the reference). The admin access reads too: whether the FortiGate Cloud API user may read `cmdb/system/admin` and `cmdb/system/api-user` (a profile without admin read access gets 403), and the shape of `intf` on `cmdb/firewall/local-in-policy` (a name on older versions, a list on 7.x; read either way);
- the bodies of 429 answers. The documented quotas: Asset Management **100 calls a minute, 1,000 an hour and 10 errors an hour**; FortiGate Cloud reportedly 100 calls a second and 15 errors a minute.

Every endpoint and `client_id` is a setting, so a change on Fortinet's side needs no new image.

## Configuration

| Variable | |
|---|---|
| `FORTICLOUD_API_ID` | The IAM API user's API ID (from its credentials file). |
| `FORTICLOUD_API_PASSWORD` | Its password. Never logged; removed from every error message, as are tokens. |
| `FORTICLOUD_AUTH_URL` | Default `https://customerapiauth.fortinet.com/api/v1/oauth/token/`. |
| `FORTICLOUD_ASSET_URL` | Default `https://support.fortinet.com/ES/api/registration/v3`. |
| `FORTICLOUD_FGT_URL` | Default `https://api.fortigate.forticloud.com/forticloudapi/v1` (Global and Canada). |
| `FORTICLOUD_ASSET_CLIENT_ID` | Default `assetmanagement`. |
| `FORTICLOUD_FGT_CLIENT_ID` | Default `fortigatecloud`. |
| `FORTICLOUD_TIME_ZONE` | IANA time zone that dates are shown in, e.g. `Australia/Melbourne` (the Cititec host). Default `UTC`. See "Dates and days left". |
| `FORTICLOUD_UNTRUSTED_MARKERS` | `off` disables the `<forticloud-data>` wrapper (below). |
| `LOG_LEVEL` | `debug`, `info` (default), `warn`, `error`, to stderr. Tool arguments and secrets are never logged. |

All URLs must be https.

## Tools

| Tool | What it does |
|------|--------------|
| `forticloud_status` | Gets a token for each portal and makes one cheap read in each: FortiGates in FortiGate Cloud (online/offline) and Asset Management folders. Each portal is reported on its own. |
| `forticloud_list_accounts` | FortiGate Cloud sub-accounts (an MSSP's clients) with device and offline counts. |
| `forticloud_list_devices` | FortiGates with model, serial, firmware, sub-account and connection to FortiGate Cloud (`online`/`offline` from `tunnelAlive`), offline first. Filters: account, connection, model, firmware, name or serial. |
| `forticloud_get_device` | One FortiGate: FortiGate Cloud details and any other fields, its config backup settings, and its Asset Management record. |
| `forticloud_firmware_summary` | Devices per firmware version (oldest first) and per major version, optionally with the devices on each. |
| `forticloud_config_backup_status` | The automatic config backup settings for one device or a page of devices; stops after three errors. |
| `forticloud_search` | Devices by name, serial or account; Asset Management products by serial. |
| `forticloud_list_assets` | Registered products by serial prefix (`FG` FortiGates, `FS` switches, `FP` APs, `F` all), 25 a page, with support end and next expiry. |
| `forticloud_get_asset` | One product: every entitlement with days left, contracts, licence numbers, warranty, end of order and end of support. |
| `forticloud_list_expiring` | Entitlements that end within N days (and, if asked, ended in the last N days), soonest first. Only the latest entitlement of each type per product counts, so a renewed service is not listed. |
| `forticloud_list_contracts` | Contracts with SKU, status, terms and end date. |
| `forticloud_list_folders` | Asset Management folders (often one per client). |
| `forticloud_get_network` | One FortiGate's network, read from the device through FortiGate Cloud: interfaces, DHCP servers, routes, VIPs, IPsec VPNs and (when asked) address objects. See "Network tools". |
| `forticloud_find_ip` | Which client (sub-account), FortiGate, interface and VLAN an IPv4 address or subnet belongs to, across the online FortiGates. |
| `forticloud_get_vpn` | Whether one FortiGate's IPsec VPN failover is set up right and would take over: per tunnel the phase 1 failover settings (backup of which primary, hold-down, DPD, idle timeout, auto-negotiate, ADVPN), phase 2 selectors, live state (up, partially up, down), and the static routes and BGP neighbors over it; the primary/backup pairs with their problems; one line per remote site; SSL-VPN on or off and users connected. See "VPN tool". |
| `forticloud_get_admin_access` | How one FortiGate's management access is exposed: per WAN-facing interface whether an admin sign-in is reachable from the internet (yes, restricted, no or unknown) and why; interfaces and their allowaccess, the admin ports and lockout settings, administrators and REST API users with their trusted hosts, local-in policies and SNMP. See "Admin access tool". |
| `forticloud_get_routing` | How one FortiGate routes and fails over between WANs: static and policy routes, link monitors and SD-WAN (configured and live), every path per destination with its state (like `get router info routing-table database`), and a summary of the failover method and of which path is in use. See "Routing tool". |

17 tools, all read-only.

Lists return `total`, `count`, `offset` and `nextOffset` (Asset Management lists: `totalPages` and `nextPage`), and each response is capped at 60,000 characters. The device list is read once a minute at most and shared by the tools in one session. When FortiGate Cloud does not return the whole device list (paging stops before its advertised total), every result built on it (status, accounts, devices, firmware, config backups, search) carries `complete: false` and a `warning`, so a partial inventory is never presented as the whole fleet.

### Network tools

FortiGate Cloud proxies the FortiOS REST API of the devices it manages: `GET {FORTICLOUD_FGT_URL}/fgt/{serial}/api/v2/...` with the same `fortigatecloud` token. It works whether or not the device is managed from FortiGate Cloud, but the device must be online (its tunnel to FortiGate Cloud up). FortiOS 7 answers can be gzipped; the client unzips them (by `Content-Encoding` or the gzip magic bytes) with the same size cap as any answer.

The proxy helper (`fortiosRequest` in `src/client.ts`) is GET only and takes an endpoint **name**, never a path; a VDOM may be passed (`vdom`). Every field not on that endpoint's **allowlist** (`src/fortios.ts`) is dropped before anything leaves the client, nested lists included. There is no denylist: a FortiOS answer carries secrets on some objects (PPPoE passwords, 802.1X/EAP keys, IPsec pre-shared keys, certificates), and a field FortiOS adds later is dropped too. A test checks that no allowlisted name looks like a secret. Results are still wrapped as untrusted data (interface descriptions, aliases and comments are set on the device), and at most 6 FortiOS reads run at once.

| Section | Endpoints | Kept |
|---|---|---|
| `interfaces` | `cmdb/system/interface` + `monitor/system/interface` | name, alias, type, VLAN ID and parent, role, mode, configured and live IP in CIDR, secondary IPs, link, speed, MAC, members, allowaccess, description. `wan: true` for role wan; `publicIp: true` for an address outside RFC 1918, CGNAT (100.64/10), loopback and link-local. Interfaces with no address (except WAN ones) are hidden unless `all_interfaces`. |
| `dhcp` | `cmdb/system.dhcp/server` (+ `monitor/system/dhcp` for a lease count) | interface, ranges, netmask, gateway, DNS, domain, lease time, active leases. No reserved addresses, MACs, host names or custom options. |
| `routes` | `monitor/router/ipv4` (falls back to `cmdb/router/static`) | destination, gateway, interface, type, distance, metric, priority; default routes first and on their own. |
| `vips` | `cmdb/firewall/vip` | name, external IP, interface and port, mapped IP and port, protocol, comment. |
| `vpn` | `monitor/vpn/ipsec` + `cmdb/vpn.ipsec/phase1-interface` + `phase2-interface` | tunnel name, type, interface, remote gateway, IKE version, up/down, phase 2 local and remote subnets. Never pre-shared keys, certificates or credentials. |
| `addresses` (only when asked) | `cmdb/firewall/address` | subnet and range objects (other types counted). |

Defaults are every section but `addresses`, with up to `max_rows` (50) rows each. Each section names its source (live or configured), and the result has the device's name, account, FortiOS version and the time it was read (in `FORTICLOUD_TIME_ZONE`). If the first section's reads fail outright (not a 404), the other sections are not tried, because FortiGate Cloud allows few errors a minute.

When a FortiOS answer is longer than this server reads (each endpoint has a row cap, and lists inside a row are cut at 200), the section says `truncated: true` and lists the reads in `truncatedReads` (`kept` and `returned` rows, or nested lists cut), so a partial answer never reads as complete. When `max_rows` (or the 500-interface or 50-phase-2 listing caps) leaves rows out, the section gives `shown` and a `moreRows` note next to the real `total`.

`forticloud_find_ip` reads the configured and live interface addresses of every FortiGate that is **online** in FortiGate Cloud (or of one `account`), and matches interfaces whose subnet contains the address, or overlaps the subnet given; exact interface addresses come first. Its bounds:

- 4 devices at a time (2 reads each, under the client's cap of 6 reads in flight), each read timing out after 20 s;
- a 45 s budget for the whole call: when it runs out the call returns what it has, with `complete: false` and the devices it did not reach;
- each device's interface list is cached for 10 minutes, so calling again continues quickly; only a full read is cached;
- a device where one of the two interface reads failed (a DHCP or PPPoE WAN address is only in the live one) or was cut at the 500-row cap is listed in `partlySearchedDevices` with the read and the reason (`failed` or `truncated`), the call is `complete: false`, and the device is read again next call;
- after 6 failures (a failed device, or a failed interface read on a partly searched one) it stops asking; a 429 stops it with the usual `rate_limited` error;
- offline devices are not queried, and are listed.

### Routing tool

`forticloud_get_routing` takes a `serial`, an optional `vdom` and `max_rows` (default 50, at most 500: static routes, policy routes, SD-WAN rules and route candidates listed). It makes up to 11 FortiOS reads (10 on a current FortiGate; the 11th is the SD-WAN fallback below): the static routes first and alone (if the device does not answer, nothing else is tried), then the rest at once.

| Part | Endpoints | Kept |
|---|---|---|
| `staticRoutes` | `cmdb/router/static` | seq-num, destination (or address object), gateway, interface, distance, priority, weight, status, blackhole, dynamic gateway, SD-WAN zone (`sdwan-zone` on 7.x, `sdwan` on 6.4, `virtual-wan-link` on 6.2), link-monitor exempt, VRF, comment. |
| `policyRoutes` | `cmdb/router/policy` | seq-num, status, action, input interfaces, source and destination, protocol and ports, gateway, output interface, comment. |
| `linkMonitors` | `cmdb/system/link-monitor` + `monitor/system/link-monitor` | name, interface, servers, protocol, gateway IP, interval, probe timeout, failtime, recoverytime, update-static-route, update-cascade-interface, status; live alive/dead, latency, jitter and packet loss per interface. |
| `sdwan` | `cmdb/system/sdwan` (`cmdb/system/virtual-wan-link` on 6.2 and older, chosen by the FortiOS version, and tried when `system/sdwan` answers 404) + `monitor/virtual-wan/health-check` + `monitor/virtual-wan/members` | status, zones, members (interface, gateway, priority, cost, weight, status), health checks (server, protocol, members, SLA targets, update-static-route; live state, latency, jitter, packet loss and SLA targets met per member), rules (mode, source, destination, priority members and zones, health checks and SLA). No TWAMP password. |
| `routeCandidates` | the static routes and SD-WAN members above + `monitor/router/ipv4`, with `monitor/system/interface` and `monitor/vpn/ipsec` for the reasons | every path per destination, sorted by destination then distance: gateway, interface (tunnels included), distance, priority, weight, source (`static`, `connected`, `sdwan`, `other`) and state. |
| `summary` | all of the above | `failover` (`sdwan`, `static-routes-with-link-monitor`, `static-routes-distance-priority` or `unknown`) with a sentence that says why; `paths`, one line per default route and remote subnet that has a backup or a path down; the default routes and the active one; caveats. |

An example of `summary.paths`:

```
Internet (0.0.0.0/0): wan2 active (distance 1); wan1 via 192.0.2.1 (distance 1) is down: link-monitor lm-wan1 reports wan1 dead; backup wan1 via 192.0.2.9 at distance 5.
203.0.113.0/25: tunnel-a active (distance 15); tunnel-b (distance 10, preferred) is down: tunnel tunnel-b is down.
```

FortiOS's REST API has no documented read of the routing-table database (`monitor/router/ipv4` lists only the installed routes, like `get router info routing-table all`), so `routeCandidates` is derived, and its `source` says so: every configured static route (disabled ones included, and an SD-WAN route as one path per member) merged with the connected and installed routes of the live table. A path is `active` when it is installed and preferred; `standby` when it is valid but a lower distance or priority route wins; `inactive` when it is out of the table, with the likely reason the data shows: disabled in config, a link-monitor (with update-static-route) reporting its interface or gateway dead (never for a route with `link-monitor-exempt`, or one outside the monitor's own `route` list), an SD-WAN health check reporting the member down, a tunnel down, or an interface link down. When the live table cannot be read, no path has a state. Paths compete only within one VRF (a path in another VRF is listed with its `vrf`), and a disabled route is never matched to an installed one.

`summary.failover` is `unknown`, not a guess, when the read that tells the methods apart failed: the SD-WAN settings (SD-WAN cannot be ruled out) or, without SD-WAN, the link monitors. It is `unknown` too when the only default route is learned by a routing protocol (BGP, OSPF...): failover then follows that protocol, and the text says so. A link-monitor counts as WAN failover only when it can remove a default route.

Every read reports on its own. A part that could not be read says which read and why (`reason`: `not_supported` for a 404, `permission_denied` for a 401 or 403, `rate_limited` with `retryAfterSeconds`, `failed`, or `not_tried`), and the others still show. The top of the result lists them in `unreadable`, names cut answers in `truncatedReads` (each part has the `truncated` details too, as in `forticloud_get_network`) and says `complete: false`. After a 429 no further read is started and `rateLimited` gives the wait; when nothing at all could be read, the tool returns the usual `rate_limited` error. The reads use the `fortigatecloud` token like the network tools and need nothing more of the API user; a FortiGate that refuses one table answers 403, reported as `permission_denied` for that part only.

### VPN tool

`forticloud_get_vpn` takes a `serial`, an optional `vdom`, an optional `tunnel` (a phase 1 name: only that tunnel and the other tunnels to the same site) and `max_rows` (default 50, at most 500 tunnels listed). It makes 10 FortiOS reads: the phase 1 interfaces first and alone (if the device does not answer, nothing else is tried), then the rest at once.

| Part | Endpoints | Kept |
|---|---|---|
| `tunnels` | `cmdb/vpn.ipsec/phase1-interface` + `cmdb/vpn.ipsec/phase2-interface` + `monitor/vpn/ipsec`, with `cmdb/router/static` for the routes and `monitor/virtual-wan/members` for SD-WAN membership | Phase 1: interface, remote gateway (or DDNS name), type, IKE version, mode-cfg, `monitor` (as `backupOf`: this tunnel is the backup of that primary), monitor-min, monitor hold-down type, delay and time, DPD mode, retry count and interval, idle timeout, auto-negotiate, NAT keepalive, net-device, add-route (with its distance and priority), exchange-interface-ip, ADVPN sender, receiver, forwarder and shortcuts, comment. Phase 2: local and remote selectors, auto-negotiate, keepalive; live state, live selectors, bytes in and out, seconds to rekey. Live: `up` (every phase 2 up), `partially up` (some; a configured selector the live read does not list counts as not negotiated) or `down`, remote gateway, bytes in and out, `creationTime` as FortiOS gives it; a dial-up server counts its connected peers. The static routes whose interface is the tunnel (destination, gateway, distance, priority, status), the BGP neighbors over it, and `sdwanMember`. **Never** `psksecret`, `psksecret-remote`, `auto-discovery-psk`, certificates, PPKs, peer IDs, XAUTH or EAP users and passwords, or dial-up user names. |
| `pairs` | from `tunnels` | One per phase 1 `monitor`: primary, backup, `backupOnlyWhenPrimaryDown`, the hold-down in words, both states, `state` (`primary up, backup idle` is the healthy one; `failed over`, `both down`, `both up`), `healthy` and `problems`: both down, the backup up while the primary is up (expected only during a delay or time hold-down), DPD off on the primary (failover slow or never), the primary only partly up (the backup stays idle), no route using the backup (it comes up but carries no traffic), a subnet the primary carries and the backup does not. |
| `bgp` | `cmdb/router/bgp` + `monitor/router/bgp/neighbors`, with `cmdb/system/interface` for the tunnel addresses | AS, router ID; per neighbor: address, remote AS, interface, update-source, description, shutdown, BFD, live state, admin status, local address (uptime and prefixes received only if the device returns them), and the `tunnel` it runs over (its interface or update-source, or its address in the tunnel interface subnet); neighbor groups and ranges, and live neighbors from a range (ADVPN hubs). No neighbor passwords. A BGP read that answers 404 is `not_supported` and the rest still shows. A tunnel with a BGP neighbor counts as carrying routes. |
| `sslVpn` | `cmdb/vpn.ssl/settings` + `monitor/vpn/ssl` | On or off (`status` on 7.4 and later, else whether it has a listening interface), port, listening interfaces, users connected (a count only: no user names, addresses or times are kept). No server certificate. |
| `summary` | all of the above | A count line; `sites`, one plain line per remote site (problems first, at most 30); caveats. |

Tunnels are grouped per remote site by their `monitor` setting, by static routes to the same subnet, and (the rest) as SD-WAN members. For example:

```
to-hq-fibre / to-hq-4g: primary to-hq-fibre up (DPD on-idle 3x20s); backup to-hq-4g idle (monitor of to-hq-fibre, fails back 60 s after the primary returns); routes 203.0.113.0/24 distance 10/15. Failover should work.
to-dc-fibre / to-dc-4g: primary to-dc-fibre up (DPD on-idle 3x20s); backup to-dc-4g idle (monitor of to-dc-fibre); routes 198.51.100.0/24 distance 10 (only via to-dc-fibre). Problems: backup to-dc-4g has no route using it: it will come up but carry no traffic.
```

Two tunnels to one subnet without `monitor` are reported as failover by route distance (both stay up; DPD off on either is a problem, because a dead tunnel would keep its routes; so is a subnet routed over only one of them). A BGP neighbor that is shut down (or admin down) is listed in `bgpNeighborsShutdown` and does not count as a route. SD-WAN member tunnels are flagged and pointed to `forticloud_get_routing`, which has the health checks and SLA state; this tool does not read the SD-WAN settings. Policy routes are not read, so a tunnel used only by a policy route is reported with no route (a caveat says so). Policy-based tunnels (`vpn ipsec phase1`, not `phase1-interface`) are not read.

Reads report on their own exactly as in the routing tool (`unreadable`, `truncatedReads`, `complete: false`, `rateLimited`; after a 429 no further read is started). When the static routes or SD-WAN membership could not be read, "no route" is not claimed; when the live state could not be read, no pair is called healthy. When the live tunnel list was cut, a tunnel missing from it has no `status` (unknown, not down), and a pair with it is not called healthy.

### Admin access tool

`forticloud_get_admin_access` takes a `serial` and an optional `vdom`. It makes 7 FortiOS reads, plus 1 (`cmdb/firewall/address`) when a local-in policy names an address object: 8 at most. `cmdb/system/global` goes first and alone (if the device does not answer, nothing else is tried), then the other six at once, then the address objects when needed.

| Part | Endpoint | Kept |
|---|---|---|
| `adminSettings` | `cmdb/system/global` | HTTPS, HTTP, SSH and telnet ports, telnet on or off, HTTP to HTTPS redirect, idle timeout, lockout threshold and duration, maintainer account. Nothing else from `system global`. |
| `interfaces` | `cmdb/system/interface` | Per interface that allows anything or faces the internet: name, alias, role, type, status, IPv4 (and secondary) address, IPv6 address, `management` (the sign-in services https, http, ssh, telnet allowed on IPv4), `ipv6Management`, `other` (ping, snmp, fgfm and the rest), `wanFacing` (role wan, or a public address). |
| `administrators` | `cmdb/system/admin` | Name, profile, VDOMs, trusted hosts (IPv4 and IPv6; 0.0.0.0/0 and ::/0 count as none), `anyIpv4Host`/`anyIpv6Host`, two-factor, wildcard, remote group, and `noTrustedHost` (the names). **Never** the password or its hash, SSH public keys or the FortiToken. |
| `apiUsers` | `cmdb/system/api-user` | Name, profile, VDOMs, trusted hosts. **Never** the API key. |
| `localInPolicies` | `cmdb/firewall/local-in-policy` (+ `cmdb/firewall/address`) | ID, interfaces, sources (an address resolved as `name (subnet)`), destinations, services, negate switches, action, schedule, status, comment. |
| `snmp` | `cmdb/system.snmp/community` + `cmdb/system.snmp/user` | Communities by `id` (the community name is the community string, so it is **never** shown), status, query and trap v1/v2c, hosts (IPv4 and IPv6, with interface and type), `pollableFromAnyHost`. v3 users: name, status, security level, queries, query port, trap status, notify hosts. **Never** the authentication or privacy password or protocol. |
| `summary` | all of the above | A count line; `internetManagement`, one entry per WAN-facing interface (`interface`, `alias`, `wanFacing`, `services`, `internetManagement`, `reason`); caveats. |

`summary.internetManagement` per WAN-facing interface:

- **yes**: a sign-in service (https, http, ssh, telnet; telnet only when `admin-telnet` is not disabled) is allowed, at least one administrator has no trusted host (or, for https/http, a REST API user), and no local-in policy denies it.
- **restricted**: every administrator (and REST API user, for https/http) has trusted hosts (they are listed), or an enabled, always-on local-in deny on that interface from everywhere (or from everywhere except a negated list) covers every allowed sign-in service; the sources let in are named. A service object covers a sign-in service when it is `ALL`, `ALL_TCP`, or the service's own object (`HTTPS`, `SSH`...) while the admin port is the default.
- **no**: no sign-in service is allowed on that interface.
- **unknown**: a read the answer depends on failed (it says why, with the HTTP status) or was cut. "no" or "restricted" is never given on missing data.

Reads report on their own as in the routing tool (`unreadable` with `httpStatus`, `truncatedReads`, `complete: false`, `rateLimited`; after a 429 no further read is started); a section that could not be read shows its read, reason and HTTP status with `note: "unavailable"`. IPv6 local-in policies (`local-in-policy6`) and address groups are not read.

### Dates and days left

One rule for every tool:

- **`daysLeft`** counts whole 24-hour periods from now to the exact expiry moment, rounded down, and is worked out from FortiCloud's original timestamp. It does not depend on a time zone. `0` means it ends within the next 24 hours (later today included); a negative number means it has ended (`-1` within the last 24 hours).
- **Dates shown** (`end`, `start`, the `window` of `forticloud_list_expiring`) are calendar dates. A FortiCloud time with an offset (Asset Management writes times like `...-8:00`) or an epoch number is shown as the date it falls on in `FORTICLOUD_TIME_ZONE`. A date with no zone (end-of-support dates, for example) is shown as written.
- Something with several end dates (a contract's terms) takes the latest **moment**, not the latest text. Contracts, their terms, entitlements and licences all use the same calculation, so they always agree.

### Untrusted text

A FortiGate's host name and description are set on the device by whoever administers it, and asset descriptions and folder names are free text. Every result except `forticloud_status` is wrapped in a `<forticloud-data>` block followed by a reminder that it is data, not instructions. A closing tag inside the data is neutralized, so it cannot end the block early. This is a label, not a guarantee; what bounds the damage is that every tool is read-only.

### Rate limits

A 429 (or a 503 with a wait) on a read is retried once when the wait is 10 s or less. Otherwise the tool returns an error that says `Try again in N s.` with `structuredContent: { error_type: "rate_limited", retry_after_seconds: N }` (60 s when FortiCloud gives no wait). Every request this server makes is a read: Asset Management's POSTs are queries. Writes would never be retried, but there are none. The Cititec MCP host also applies its own per-service budget. `forticloud_get_routing`, `forticloud_get_vpn` and `forticloud_get_admin_access` are the exceptions to "a 429 stops the call": once one has read something, it stops asking and returns what it has, with the parts it could not read marked `rate_limited` and the wait in `rateLimited.retryAfterSeconds` (see "Routing tool", "VPN tool" and "Admin access tool").

## Development

```bash
npm ci
npm run lint    # tsc --noEmit
npm test        # vitest
npm run build   # tsup -> dist/index.js
```

## Docker

```bash
docker build -t forticloud-mcp .
docker run --rm -i --env-file forticloud.env forticloud-mcp
```

stdio only: the Cititec MCP host runs one container per connection with the service's env file. The **Cititec release** workflow tags a release with semantic-release on every merge to `main` and pushes `ghcr.io/cititec-pty-ltd/forticloud-mcp:vX.Y.Z` (and `:latest`).

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
