# Glossary

Terms used across the README and the guides, in alphabetical order.

| Term | Meaning |
|------|---------|
| **Apex** | The bare domain itself, written `@` as a host. |
| **Authenticator / TOTP** | The six-digit time-based code of the panel's second factor (RFC 6238, HMAC-SHA1, 30 second step), made from the seed. No Google app is needed, because the server computes it itself. It answers once per login. |
| **Bearer** | The `Authorization: Bearer <token>` header. Every tool call over HTTP needs the fleet `mcp-admin-token`. |
| **Bulk save mode** | A panel editor switch. It must be off, read live from the checked state of `#editor_bulk_save_mode`, or a write is refused (`bulk_save_on_or_unknown`). |
| **`confirmed`** | The write guard. False or unset previews and changes nothing. True makes the change, and only after the operator approves that exact change. |
| **`complete` / `warning`** | Fields of a records read. `complete` is true when every page and row was read. `warning` appears when the read is incomplete or empty. |
| **Container** | The `zoneedit-mcp` Docker container on the NAS, bound to loopback port 8768. |
| **Control panel (panel)** | ZoneEdit's web interface at `cp.zoneedit.com`. The server drives it in a headless Chrome. |
| **CNAME conflict** | A `CNAME` shares a host with another record, which DNS forbids. Refused as `cname_conflict`. |
| **Deadline** | The longest a browser run may take, 150 s. The run's browser is then killed (`RunDeadlineExceeded`). |
| **`destructiveHint`** | A tool annotation. It is true on `zoneedit_record_update` and `zoneedit_record_delete`, so a client can ask before running them. |
| **`differences`** | A list in a write result, present when the panel re-read did not show exactly the change. |
| **DNS read-back (`dns_readback`, `dns_matches`)** | An extra check that asks the zone's own name servers with `dig`. Informative only. |
| **Domain** | One zone of the account, such as `example.net`. Read from the panel, never built in. |
| **DYN** | A dynamic DNS record type, kept fresh by an update client. |
| **`expect_content` / `expect_hash`** | The arguments that name the row an update or delete acts on. Matched exactly. |
| **Fields** | The form inputs of a record type, such as a CAA tag or an SRV port. Read from the live form by `zoneedit_schema`. |
| **Fleet token** | The shared `mcp-admin-token`. Only its SHA-256 hash is configured on the server. |
| **Gate** | The bearer check around every tool call. It fails closed. |
| **Hash** | A row's `data-hash` from the panel, returned by `zoneedit_records`. It names one row for update and delete. |
| **Headless Chrome** | Chrome with no window, driven by Patchright. |
| **Host** | The label of a record inside the domain, such as `www`, or `@` for the apex. |
| **Latch** | The 900 s block on new logins after a login or code failure. Held in process memory. Cleared by a restart or `zoneedit_2fa_latch_clear`. |
| **NS** | A name server record. The apex NS rows name the zone's own servers. |
| **`ok` / `refused`** | Result fields. `ok` is true only when the call did what was asked and, for a write, the panel re-read shows it. `refused` carries a code and means nothing was changed. |
| **Outcome unknown** | A failure after the final Save or Delete click. The change may have landed, so read the zone before retrying. |
| **Panel re-read (`panel_verified`, `verified`)** | After a confirmed write, every panel page is read again. `panel_verified` and `verified` carry the same value, true only when the re-read shows the change. |
| **Patchright** | The browser automation library that drives Chrome. Only `zoneedit_session.py` imports it. |
| **Pending** | A row the panel shows as queued, queued for deletion or revoked. It is not published and never verifies a write. |
| **Preview** | A write call without `confirmed`. It logs in, reads the panel and returns `before` and `after`. |
| **Replace prompt** | The panel's Confirm button or warning shown when a save would replace a row. The tool stops (`replace_prompt_shown`) and never clicks it. |
| **Row** | One record as the panel lists it: type, host, content, TTL, hash, pending. |
| **Schema** | The record types and, for each, the form fields, options and TTL labels the panel offers. |
| **Second factor** | The Authenticator code page some logins show. The server answers it once, from the seed. |
| **Seed** | The base32 TOTP secret in the vault entry `zoneedit-panel-totp-seed`. It is the `secret=` value of the enrolment QR. Never returned, logged or echoed. |
| **Recovery code** | The one-time code the panel shows at enrolment. Using it turns two-factor off. Keep it in your own vault, never on the server. |
| **Serving module** | One of the eight `zoneedit_*.py` files the Dockerfile copies. A change to one needs a version bump. |
| **SOA** | The start of authority record. It governs how the zone is served. |
| **stdio** | A local transport with no bearer gate, chosen with `--transport stdio`. |
| **Streamable HTTP** | The network transport the server uses by default. |
| **`tools/call` / `tools/list`** | The MCP requests that run a tool and that list tools. Over HTTP `tools/call` needs the bearer. `tools/list` does not. |
| **TTL (label)** | Time to live, the seconds a record may be cached. The panel names it in text, such as `1 hour`. |
| **Vault** | The credential store, read through a CLI script that prints a named entry to stdout. |
| **Version of record** | `__version__` in `zoneedit_server.py`, equal to `pyproject.toml` and reported by `initialize`. |
| **Write guard** | The set of protections on a write: preview by default, `confirmed`, the warnings in the tool text, the `destructiveHint` annotation on update and delete, and the panel re-read. |
| **Zone** | All the DNS records of one domain. |
