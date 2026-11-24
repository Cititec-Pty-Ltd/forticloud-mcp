# Changelog

Releases are cut by semantic-release from the commit messages on `main` (the
"Cititec release" workflow); it adds an entry above this line for each release
and publishes the image to `ghcr.io/cititec-pty-ltd/forticloud-mcp`.

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
- Paged and bounded results; results with device-supplied text are wrapped in
  `<forticloud-data>` as untrusted data.
- Fleet 429 policy: a read is retried once when the wait is 10 s or less,
  otherwise a structured `rate_limited` error with `retry_after_seconds`.
