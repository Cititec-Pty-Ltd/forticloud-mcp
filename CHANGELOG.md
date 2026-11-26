# Changelog

Releases are cut by semantic-release from the commit messages on `main` (the
"Cititec release" workflow); it adds an entry above this line for each release
and publishes the image to `ghcr.io/cititec-pty-ltd/forticloud-mcp`.

## 1.3.1

- `forticloud_get_vpn`: a backup tunnel with BGP neighbors no longer skips the
  phase 2 selector check. Its selectors must still cover the primary's routed
  traffic, or the pair is not called healthy. Only the static route check is
  skipped for it, since BGP can bring those routes. Parameters and output
  fields are unchanged.

## 1.3.0

A read-only VPN tool, so a tech can tell whether a FortiGate's IPsec VPN
failover is set up right and would take over.

- 1 new tool (16 in all): `forticloud_get_vpn`, for one FortiGate by serial
  (and VDOM, and optionally one tunnel and the rest of its site): per IPsec
  tunnel the phase 1 failover settings (`monitor`, its hold-down, DPD, idle
  timeout, auto-negotiate, keepalive, net-device, add-route,
  exchange-interface-ip, ADVPN), the phase 2 selectors, the live state (up,
  partially up or down, per phase 2, with bytes), the static routes and BGP
  neighbors over it, and SD-WAN membership. `pairs` checks each
  primary/backup pair (healthy is primary up and backup idle; problems:
  both down, backup up while the primary is up, DPD off on the primary, the
  primary only partly up, no route using the backup, a subnet only the
  primary carries). `summary.sites` says per remote site whether failover
  should work. Also BGP neighbors (matched to tunnels) and SSL-VPN on or off
  with the number of users connected.
- Each read reports on its own, as in `forticloud_get_routing`: a BGP or
  SSL-VPN endpoint that answers 404 is `not_supported` and the rest still
  shows; after a 429 no further read is started.
- 7 new FortiOS endpoints on the allowlist (phase 1 and phase 2 with the
  failover fields, live IPsec with byte counters, BGP settings and live
  neighbors, SSL-VPN settings and a session count). Pre-shared keys, the
  ADVPN key, certificates, PPKs, peer IDs, XAUTH/EAP credentials, BGP
  passwords and SSL-VPN user names are never on a list.

## 1.2.0

A read-only routing tool, so a tech can tell how a dual-WAN FortiGate fails
over without the GUI or CLI.

- 1 new tool (15 in all): `forticloud_get_routing`, for one FortiGate by
  serial (and VDOM): static routes with every routing field, policy routes,
  link monitors (configured and live), SD-WAN (configured and live; `system
  virtual-wan-link` on FortiOS 6.2 and older), and `routeCandidates`, every
  path per destination like `get router info routing-table database`
  (derived from the configured routes and the live table, since FortiOS has
  no documented REST read of the database), each active, standby or inactive
  with the likely reason. The summary names the failover method (SD-WAN,
  static routes with link-monitor, distance/priority alone, or unknown) and
  says per default route and remote subnet which path is in use and which
  are backups or down.
- Each read reports on its own when it is not supported, denied, rate
  limited, failed or truncated; one failure never hides the rest. After a 429
  no further read is started; if nothing could be read, the usual
  `rate_limited` error.
- 10 new FortiOS endpoints on the allowlist (static and policy routes,
  link-monitor, SD-WAN and virtual-wan-link settings, link-monitor,
  health-check and SD-WAN member state). The allowlist can now keep a list
  of plain values (SLA targets met), read a single settings object and a
  name-then-interface map, and keeps a plain value where a FortiOS version
  has one instead of a list.

## 1.1.0

Read-only network tools, through FortiGate Cloud's FortiOS API proxy.

- 2 new tools (14 in all): `forticloud_get_network` (interfaces, DHCP, routes,
  VIPs, IPsec VPNs and address objects of one FortiGate, live or configured)
  and `forticloud_find_ip` (which client, device, interface and VLAN an IPv4
  address or subnet belongs to).
- A FortiOS proxy helper in the client: GET only, a fixed list of endpoints,
  an optional VDOM, and a per-endpoint field allowlist applied before
  anything leaves the client, so secrets (PPPoE passwords, 802.1X keys,
  pre-shared keys, certificates) never appear. At most 6 reads in flight;
  gzipped answers are unzipped.
- `forticloud_find_ip` reads online devices 4 at a time within a 45 s budget,
  caches each fully read device for 10 minutes, marks a device whose live or
  configured interface read failed as partly searched (`complete: false`, not
  cached), stops after 6 failed devices, and
  returns partial results naming the skipped and offline devices.

## 1.0.0

First release: a read-only MCP server for Fortinet FortiCloud (FortiGate Cloud
and Asset Management), stdio transport.

- 12 tools: `forticloud_status`, `forticloud_list_accounts`,
  `forticloud_list_devices`, `forticloud_get_device`,
  `forticloud_firmware_summary`, `forticloud_config_backup_status`,
  `forticloud_search`, `forticloud_list_assets`, `forticloud_get_asset`,
  `forticloud_list_expiring`, `forticloud_list_contracts`,
  `forticloud_list_folders`.
- FortiCloud IAM API user (`FORTICLOUD_API_ID`, `FORTICLOUD_API_PASSWORD`);
  one OAuth token per portal, cached until two minutes before it expires; a
  refused sign-in is not retried for 10 minutes (repeated failures can lock
  the API user out).
- Endpoints and client IDs are settings with documented defaults.
- `daysLeft` counts 24-hour periods to the exact expiry (time-zone independent);
  dates are shown in `FORTICLOUD_TIME_ZONE` (default UTC). Contracts,
  entitlements and licences share one expiry calculation.
- Paged and bounded results; results with device-supplied text are wrapped in
  `<forticloud-data>` as untrusted data.
- Fleet 429 policy: a read is retried once when the wait is 10 s or less,
  otherwise a structured `rate_limited` error with `retry_after_seconds`.
