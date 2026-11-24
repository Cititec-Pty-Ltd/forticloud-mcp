# FortiCloud MCP server

A read-only MCP server for [Fortinet FortiCloud](https://support.fortinet.com). Claude can ask which FortiGates are offline in FortiGate Cloud, what firmware they run, how their config backups are set, and, from Asset Management, which support and FortiGuard entitlements expire soon.

It uses the same framework as Cititec's other MCP servers: TypeScript, `@modelcontextprotocol/sdk`, a stdio transport, vitest tests, tsup and a Docker image.

## The APIs

One FortiCloud **IAM API user** reaches two portals, each with its own OAuth token:

| Portal | API | Token `client_id` |
|---|---|---|
| **FortiGate Cloud** (being renamed FortiManagement Cloud) | `GET https://api.fortigate.forticloud.com/forticloudapi/v1/...` (`/devices`, `/devices/{sn}`, `/devices/{sn}/configbackups/setting`, `/subaccounts`) | `fortigatecloud` |
| **Asset Management** v3 | `POST https://support.fortinet.com/ES/api/registration/v3/...` with a JSON query (`products/list`, `products/details`, `contracts/list`, `folders/list`) | `assetmanagement` |

- **Tokens:** `POST https://customerapiauth.fortinet.com/api/v1/oauth/token/` (the trailing slash matters) with `{username: <API ID>, password, client_id, grant_type: "password"}`. The token is cached for its `expires_in` less two minutes. A token that FortiCloud rejects early (HTTP 401) is replaced once.
- **Failed sign-ins:** FortiCloud answers bad credentials with HTTP 400 `invalid_grant`. Repeated failures are reported to lock the API user out of every portal for 15 to 30 minutes, so after a refusal this server does not try to sign in again for 10 minutes.
- **Regions:** FortiGate Cloud has Global (which is also Canada), US, Europe and Japan hosts (`api.`, `usapi.`, `euapi.`, `jpapi.fortigate.forticloud.com`). The API only shows the region you call. The token and Asset Management hosts are global.
- **Read-only:** every Asset Management call this server can make is one of its read endpoints (a fixed list in `src/client.ts`), and FortiGate Cloud is only called with GET. The other Asset Management v3 endpoints (register, decommission, transfer, folders/create...) are not reachable. Give the API user a **read-only** permission profile anyway.

### What is not confirmed yet

Fortinet's full API reference (FNDN) needs a login. The endpoints and fields above come from Fortinet's public docs and KB articles and from open-source clients. These are handled defensively and need a live check:

- the token lifetime (14,400 s, 3,660 s and 3,600 s are all reported); the server uses whatever `expires_in` says;
- FortiGate Cloud `/devices` paging (`limit` and `offset`): the server stops on a short page, on a page with nothing new, or at the `total` the items carry;
- a "last seen" time on a device: the public sample has none, so `lastSeen` is filled from any of several likely field names, and `forticloud_get_device` shows every other field the API returns (`otherFields`);
- a list of config backup revisions: only the automatic backup settings (`configbackups/setting`) are documented;
- `/subaccounts` (account names), Asset Management's page size (25) and `totalPages`, and the fields `folderPath` and `status` on list items;
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

Lists return `total`, `count`, `offset` and `nextOffset` (Asset Management lists: `totalPages` and `nextPage`), and each response is capped at 60,000 characters. The device list is read once a minute at most and shared by the tools in one session. When FortiGate Cloud does not return the whole device list (paging stops before its advertised total), every result built on it (status, accounts, devices, firmware, config backups, search) carries `complete: false` and a `warning`, so a partial inventory is never presented as the whole fleet.

### Untrusted text

A FortiGate's host name and description are set on the device by whoever administers it, and asset descriptions and folder names are free text. Every result except `forticloud_status` is wrapped in a `<forticloud-data>` block followed by a reminder that it is data, not instructions. A closing tag inside the data is neutralized, so it cannot end the block early. This is a label, not a guarantee; what bounds the damage is that every tool is read-only.

### Rate limits

A 429 (or a 503 with a wait) on a read is retried once when the wait is 10 s or less. Otherwise the tool returns an error that says `Try again in N s.` with `structuredContent: { error_type: "rate_limited", retry_after_seconds: N }` (60 s when FortiCloud gives no wait). Every request this server makes is a read: Asset Management's POSTs are queries. Writes would never be retried, but there are none. The Cititec MCP host also applies its own per-service budget.

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
