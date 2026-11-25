# Changelog

Releases are cut by semantic-release from the commit messages on `main` (the
"Cititec release" workflow); it adds an entry above this line for each release
and publishes the image to `ghcr.io/cititec-pty-ltd/forticloud-mcp`.

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
