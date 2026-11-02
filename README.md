# zoneedit-mcp

MCP server for the DNS records of the domains on one ZoneEdit account, read and changed through the ZoneEdit
control panel (cp.zoneedit.com) in a headless Chrome driven by Patchright. Only the panel login is configured:
the domains, record types, form fields, option lists, TTL labels, editor settings and name servers are read
from the account on every call. Streamable HTTP,
bearer-gated, in the same shape as the sibling `amt-mcp`.

## Documentation

| Document | For |
|----------|-----|
| This README | What the server is, the tools, the environment, deploy and the redeploy runbook. |
| [Operator's guide](docs/operators-guide.md) | Reading and changing records safely, step by step. |
| [Install guide](docs/install-guide.md) | Prerequisites, vault entries, the stdio and HTTP runs, and the install check. |
| [Troubleshooting](docs/troubleshooting.md) | Symptom, cause and action for every refusal, login fault and run fault. |
| [Glossary](docs/glossary.md) | The terms used above. |
| `CLAUDE.md` | Guardrails for coding agents working in this repo. |
| [LICENSE](LICENSE) | DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE, version 2 (WTFPL). |

**Update the guides when** a tool, an argument, a refusal code, a dependency, an environment variable or a vault entry changes. The same commit that changes the code changes the guide.

## Where it runs

- **Container** `zoneedit-mcp` on a NAS, deploy directory `/volume1/docker/zoneedit-mcp`, published on the NAS loopback `127.0.0.1:8768` only (layout and build in [Deploy](#deploy)).
- **Clients** reach it at `https://zoneedit.example.net/mcp`: a LAN-only DSM reverse-proxy rule on 443 (the `LAN Only` access profile) in front of the loopback port, and a dnsmasq LAN name `zoneedit.example.net` pointing at the NAS. Claude Code registers it in the workspace `.mcp.json` as an `http` server with `headersHelper` (`mcp_admin_headers.py`), so no agent handles the fleet token.
- **Auth:** every `tools/call` needs the fleet `mcp-admin-token` bearer. `initialize` and `tools/list` need no token and return only names, descriptions and the server version. Prove the gate with a tokenless `tools/call`, never with `tools/list`.
- **Proven live (2026-11-01 and 2026-11-02):** login with the Authenticator code page, the three-page read, `zoneedit_domains`, `zoneedit_schema` (31 types), and write PREVIEWS of A, AAAA, TXT, MX, CAA, SRV, URL, DMARC, PARK and SSHFP against the live schema (nothing saved). **Proven live on version 1.1.1 only:** a TXT add and its delete, and a CNAME add and delete. The write path was rebuilt after that (schema read, generic field fill, row-set verification), so **no version since 1.1.1 has a confirmed live write of any type.** **Not proven live:** `zoneedit_record_update`, a confirmed write of any type on the current code, a write of the apex A, NS, SOA or DYN, a further row beside an existing host and type, and whether the panel keeps every other row's `hash` across a write. The verification assumes it does, and hashes are only known to be stable across logins. The first confirmed write needs one operator-approved throwaway record.
- **Running version:** the repo is ahead of the container. On 2026-11-02 the repo `__version__` was 1.9.1 and the NAS container ran 1.1.1. Nothing newer is deployed, and the repo has no git remote, so nothing is pushed. Read the running version back with `initialize` (see the runbook).

## Tools

| Tool | Title | What it does |
|------|-------|--------------|
| `zoneedit_records` | ZoneEdit Records | Reads every DNS page and returns the records. Optional `host` filter (`@` for the apex). Returns coverage fields: `read`, `panel_total`, `pages_read`, `pages_expected`, `complete`, `matched`, and a `warning` when the read is incomplete or empty. |
| `zoneedit_selftest` | ZoneEdit Self-Test | Logs in once (answering the second factor from the TOTP seed when asked) and reads DNS page 1. Returns `login`, `dns_page`, `panel_total`, `pages`, `bulk_save_off`, `second_factor` (`answered` when the code page was met, `not_asked` for a password-only login, `unknown`) and `seed` (`present` or `absent` after an answered code page, else `not_read`), or `{ok: false, error_type}`. `error_type` is `second_factor_required` (no usable seed), `second_factor_rejected` (the code page still shows after the one submit), `login_latched` (a failure in the last 900 s blocks new attempts), `login_failed`, `RunDeadlineExceeded`, `RunBusy`, or a type name. |
| `zoneedit_domains` | ZoneEdit Domains | Lists the account's domains from the panel's domain list: `domains`, `default` (set only when the account has exactly one), `count`, `total` and `complete` (the list holds all of the "out of N total"). |
| `zoneedit_schema` | ZoneEdit Record Schema | Reads one domain's record types from the add form, each with its fields (`name`, `label`, `kind`, `required`, `disabled`, `placeholder`, select `options`), plus `ttl_options`, the editor `settings` and an `unsettled` list. Takes `domain` and an optional `record_type`. Selects types and reads the form, never submits. About 65 s for all 31 types, a few seconds for one. Refusals: `bad_domain`, `unknown_domain`, `domain_required`, `unknown_record_type`. |
| `zoneedit_2fa_status` | ZoneEdit 2FA Status | Reports the second-factor state without logging in and without a browser: `seed` (`present`, `absent` or `invalid`, by name only), `last_second_factor`, `latch_seconds_left`, `last_submitted_step`, `step_seconds_left`, `epoch`. Never the seed or a code. |

The five read tools are read-only (`readOnlyHint: true`). `zoneedit_records` also takes an optional `domain` that must be on the account's list. With an empty `domain` the account's only domain is used. The state they report lives in the server process and is cleared by a container restart.

### Write tools

| Tool | Title | What it does |
|------|-------|--------------|
| `zoneedit_record_add` | ZoneEdit Add Record | Adds one record of any type `zoneedit_schema` lists. The apex A, NS and SOA steer the whole zone and DYN rows belong to update clients, so the tool text says to preview those first. Adds a further row beside any of the same host and type, such as a second `MX` or `TXT`. Refuses on any CNAME conflict. |
| `zoneedit_record_update` | ZoneEdit Update Record | Changes one row read in the same call, identified by exact `expect_content` and/or `expect_hash`. |
| `zoneedit_record_delete` | ZoneEdit Delete Record | Deletes one row read in the same call, matched by host, type and exact `expect_content` and/or `expect_hash`. |
| `zoneedit_2fa_latch_clear` | ZoneEdit Clear Login Latch | Clears the 900 s login latch so the next login may run. Previews the seconds left unless `confirmed=true`. Touches no panel and no DNS. Clear it only after the cause of the failure is checked, because a repeated failed login can lock the panel account. |

**Where the guard lives.** Mutations are guarded by the tool text, the annotations and the `confirmed` write guard, never by refusing a record type or host. `zoneedit_record_update` and `zoneedit_record_delete` declare `destructiveHint: true`. The apex A, NS and SOA steer the whole zone and a DYN row is kept fresh by update clients, so each write tool's text says to preview those first and confirm only on the operator's word. No refusal depends on a policy about a record type or host. The refusal codes are of four kinds: input checks (`bad_type` for a type the live schema does not list, `bad_host` for a label that is not a valid host name, `empty_content`, `bad_ttl`, `bad_prio`, `bad_caa`, `bad_field`, `unknown_field`, `field_disabled`, `bad_option`, `missing_field`, `bad_domain`, `unknown_domain`, `domain_required`), row matching (`not_found`, `content_mismatch`, `ambiguous`, `bad_hash`, `no_change`), panel state (`schema_unavailable`, `incomplete_read`, `bulk_save_on_or_unknown`, `step_failed`), and the two that keep the panel from replacing a row (`cname_conflict`, `replace_prompt_shown`).

Parameters: `domain` (a domain of the account, see `zoneedit_domains`; empty uses the account's only domain and is refused with `domain_required` when there are several), `type` (any record type from `zoneedit_schema`), `host` (bare label, `@` for the apex; a type whose schema marks the host optional, such as DMARC, takes `""` or `@` for an empty host), `expect_content` and/or `expect_hash` (update and delete: the row's current content or `hash` from `zoneedit_records`, matched exactly), `new_content` and `new_ttl`/`new_prio` (update only), `content` (for CAA the panel string `<flag> <tag> <provider>`; otherwise the value of the `content` field), `ttl` (a panel TTL label such as `1 hour`), `prio`, `fields` (any other form field by its schema name, for example `proto`, `weight`, `port`, `policy`, `https`; select values take an option's text or the part before ` - `; a checkbox takes true or false), and `confirmed` (default `false`). A disabled form field accepts only the panel's own default.

Every write previews unless `confirmed=true`. A record write's preview logs in and reads the panel and changes
nothing. The latch clear's preview does not log in and only reports the seconds left. A confirmed write re-reads every panel page, and `ok` is true only when that re-read shows
the change. Refusal codes: `bad_type`, `bad_host`, `empty_content`, `bad_caa`,
`bad_prio`, `cname_conflict`, `not_found`, `content_mismatch`, `ambiguous`,
`no_change`, `incomplete_read`, `bulk_save_on_or_unknown`, `bad_domain`, `unknown_domain`, `domain_required`, `schema_unavailable`, `bad_field`, `unknown_field`, `field_disabled`, `bad_option`, `bad_ttl`, `missing_field` (with the names), `bad_hash`, `step_failed` (with the step, before the final click). A visible Confirm
button in the panel stops the run (`replace_prompt_shown`).

DNS read-back (`dns_readback`, `dns_matches`) queries the zone's own name servers (the apex NS rows of the editor, else `dig +short NS`)
with the system `dig` (`/usr/bin/dig` on macOS). It is informative and never changes `ok`. Without
`dig` the write still verifies and `dns_readback` is `{"error": "dig_unavailable"}`.

### Behaviour notes

- A write that fails after the final Save or Delete click returns `outcome: "unknown"` (with `message` and `error_type`); read the zone before retrying.
- A confirmed write is verified by a panel re-read: the row set must show exactly the change (one new row and no other row lost for an add, the target gone and nothing else lost for a delete, nothing else lost and one row of that type and host for an update), no pending row, and the requested content and TTL where the type has them.
- A preview reads the type's form from the panel (it clicks the add button and selects the type, and submits nothing).
- Records carry `pending: true` when shown as queued, queued for deletion or revoked; a pending match never verifies a write.
- `selftest` `bulk_save_off` is read live from the checked state of `#editor_bulk_save_mode`, never from its static `value` attribute.
- Every browser run has a deadline. One run at a time holds the browser; a caller waits up to 170 s for it (`RunBusy` after that). A run still going at 150 s has its browser processes killed and raises `RunDeadlineExceeded`, which is never a credential failure. A confirmed write cut by the deadline returns `outcome: "unknown"`: read the zone before retrying.
- The browser user agent is taken from the installed Chrome (`user_agent_for`), never `HeadlessChrome`.
- The login latch (`LoginLatched`, 900 s) is in process memory. `zoneedit_2fa_status` shows it and `zoneedit_2fa_latch_clear` clears it.

## Environment

| Variable | Purpose |
|----------|---------|
| `MCP_ADMIN_TOKEN_HASH` | SHA-256 hex of the fleet `mcp-admin-token`. Required over HTTP; unset or malformed refuses every token. |
| `ZONEEDIT_TRANSPORT` | `http` (default) or `stdio`. Only an explicit `stdio` skips the bearer gate. |
| `ZONEEDIT_BIND_HOST` | Bind address, default `127.0.0.1`. |
| `ZONEEDIT_PORT` | Bind port, default `8768`. |
| `ZONEEDIT_ALLOWED_HOSTS` | Comma-separated extra Host names accepted behind an ingress. |
| `ZONEEDIT_SECRETS_CLI` | Path to a vault CLI script used to read the panel credentials. The server runs `python <cli> get <entry>` and reads the value from stdout, raw or as JSON. In the container compose sets it to `/opt/node-vault-mcp/services/secrets.py`. |
| `ZONEEDIT_CHROME_ARGS` | Extra Chromium flags, whitespace-split, read at call time. Compose sets `--no-sandbox --disable-dev-shm-usage`. |
| `ZONEEDIT_ADMIN_DEPLOY_DIR`, `ZONEEDIT_ADMIN_SSH_ENTRY` | For `deploy/zoneedit_admin.py` only (run on the machine that holds the main vault): the NAS deploy directory and the vault entry holding the NAS `ssh_cmd`. For this deployment `/volume1/docker/zoneedit-mcp/deploy` and `nas-ssh`; `ZONEEDIT_SECRETS_CLI` there is the main vault's `secrets.py`. |

The panel credentials are the vault entries `zoneedit-panel-username` and
`zoneedit-panel-password`. The panel's TOTP seed is the vault entry
`zoneedit-panel-totp-seed` (raw text, or a JSON object with a `seed` or `value` field). All three are
read in-process at call time and never returned. The seed is plain RFC 6238, so no Google app or account is needed.
Setup end to end is in the [install guide](docs/install-guide.md#2a-set-up-the-second-factor-totp). The seed and each six-digit code are never a tool
argument, logged, returned or echoed. The ZoneEdit code page was met and answered live on 2026-11-02:
`zoneedit_selftest` reported `second_factor: answered` and `seed: present`. A live selftest shows that state every time.

## Layout

- `zoneedit_gate.py`: bearer gate (fail closed).
- `zoneedit_vault.py`: vault read through the CLI, errors name the key only.
- `zoneedit_panel.py`: pure HTML parsing of panel pages (stdlib only).
- `zoneedit_totp.py`: RFC 6238 codes and the seconds left in a step (pure, stdlib only).
- `zoneedit_session.py`: the only Patchright importer; login, the one second-factor answer, the failure latch, pagination, the domain list and domain open (`read_domains`, `open_domain`), the schema reads (`schema_open`, `read_schema`), browser lifecycle, the run deadline and the kill of a stuck run's browser processes.
- `zoneedit_tools.py`: `records`, `domains`, `schema`, `selftest`, `twofa_status`, `twofa_latch_clear` and the three write wrappers as plain functions over a runner.
- `zoneedit_writes.py`: write plan rules (pure), panel page actions, re-read verification and DNS read-back.
- `zoneedit_server.py`: FastMCP assembly, tool registration, HTTP and stdio startup.
- `deploy/verify_endpoint.py`: tokenless liveness check of a mount (bare GET 406, `serverInfo`, tool count, gate refusal). `tests/test_verify_endpoint.py` pins its constants to the server.
- `tests/test_conformity.py`: conformity check on the tool list a client receives (`list_tools()`). Parameters are documented in the schema, not the docstring.
- `tests/real_browser.py`: the shared offline real-Chrome fixtures. `tests/test_schema_dom.py` runs the domain and schema reads against a synthetic editor page whose type forms re-render after a delay.
- `tests/test_clickpaths.py`: the shipped add, update, delete and pagination steps against the synthetic test pages in a real headless Chrome with the network off. Small scripts in `tests/fixtures/*.html` stand in for the panel's own JavaScript. One strict `xfail` records that the add button scan takes the last match.
- `tests/test_dynamic_writes_dom.py`: schema-driven add and update through a real offline Chrome against `tests/fixtures/write_model.html`.
- `tests/test_no_zone_in_code.py`: keeps the zone name and the DNS editor URL out of the eight serving modules.
- `tests/test_session_hardening.py`, `tests/test_totp.py`, `tests/test_2fa_tools.py`: the run deadline and kill, the login and second factor, and the second-factor tools, all offline with fakes.

## Running

```
cd <path to this repo>
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:xdist -q   # python3 must be 3.11 or newer
```

The tests use the synthetic pages in `tests/fixtures/` (invented data on example.com, written for the tests) and fake runners. They need no network and
no vault. Three files start a real Chrome (channel `chrome`, headless, every request aborted except the
synthetic pages): `tests/test_clickpaths.py`, `tests/test_schema_dom.py` and `tests/test_dynamic_writes_dom.py`.
They skip themselves when Chrome cannot launch. The full run takes about 2 minutes. For the fast offline run add
`--ignore=tests/test_clickpaths.py --ignore=tests/test_schema_dom.py --ignore=tests/test_dynamic_writes_dom.py`
(391 tests, about 10 seconds, measured 2026-11-02).

To serve over HTTP:

```
MCP_ADMIN_TOKEN_HASH=<sha256 of the token> ZONEEDIT_SECRETS_CLI=<path to secrets.py> \
  python3 zoneedit_server.py   # 3.11 or newer; the panel login needs Patchright and Chrome installed
```

## Versioning

The version of record is `__version__` in `zoneedit_server.py`, plain semver `MAJOR.MINOR.PATCH`, and `pyproject.toml` carries the same string. `build_server` sets it on the low-level server, so `initialize` reports it as `serverInfo.version` (the SDK would otherwise report its own version). It is never derived from a library or package metadata.

- **Bump with every change to a serving module** (the modules the Dockerfile copies into the image). New tool or new behaviour is MINOR, a fix is PATCH, a removed or renamed tool or a changed parameter or return shape is MAJOR. The owner judges each step. A docs-, test- or deploy-file-only change needs no bump.
- **Gate:** `hooks/version_bump_gate.py` is a repo-local pre-commit hook that blocks a commit staging a serving file while `__version__` is unchanged against HEAD. Install it once per clone with `python3 hooks/version_bump_gate.py --install`.
- **Commit subject ends with the version**, for example `Add update proof, 1.1.0`. There are no tags and no changelog; the commit is the release, and a push stays operator-gated.
- **Read the running version back after every deploy:** POST an `initialize` to the container (loopback on the NAS) and check `serverInfo.version` equals `__version__` at the deployed commit. The image tag stays `zoneedit-mcp:local`.

## Deploy

Files under `deploy/` and the root `Dockerfile` and `.dockerignore`. They hold no secret, and the
container publishes loopback only (`127.0.0.1:8768`).

- **Build:** copy `deploy/site.vars.example` to `deploy/site.vars` and fill it in, then
  `docker compose --env-file ./site.vars -f compose.yaml up -d --build` from `deploy/`. The image
  installs `dnsutils` (for `dig`) and Google Chrome (`patchright install --with-deps chrome`), and
  runs as uid 10001 inside the image.
- **NAS layout:** the repo-root files (`Dockerfile` and the eight modules) live in
  `/volume1/docker/zoneedit-mcp`. `compose.yaml`, `site.vars`, `zoneedit-mcp.env`, `vault/` and
  `node-vault-mcp/` live in `/volume1/docker/zoneedit-mcp/deploy`. `ZONEEDIT_ADMIN_DEPLOY_DIR` is
  that `deploy` path, so `vault sync` writes `deploy/vault/`, which compose mounts at `/vault` (the dedicated vault is `/vault/zoneedit-mcp.vault` beside its key file). `node-vault-mcp/`
  must hold `services/secrets.py` and `services/vault_secrets/`, because compose mounts it at
  `/opt/node-vault-mcp` and reads `/opt/node-vault-mcp/services/secrets.py`.
- **Build time:** the Chrome layer took about 55 minutes on the NAS. Build with `--progress plain`.
- **Env file:** `deploy/zoneedit-mcp.env` (mode 0600) holds `MCP_ADMIN_TOKEN_HASH=<sha256 of the fleet
  token>`. Never the token itself.
- **Vault sync:** `deploy/zoneedit_admin.py vault sync` rebuilds the NAS vault in `vault/` with only the
  three entries (`zoneedit-panel-username`, `zoneedit-panel-password`, `zoneedit-panel-totp-seed`), values passed over stdin.
  Sync prints only the three key names. It depends only on the main vault and the NAS deploy directory and
  does not check the container, which does not exist on a fresh deploy until compose has started it.
  Run `vault status` after the container starts; that is the only command that needs the container
  (`docker exec`). Requires `ZONEEDIT_SECRETS_CLI`, `ZONEEDIT_ADMIN_DEPLOY_DIR` and
  `ZONEEDIT_ADMIN_SSH_ENTRY`.
- **Chrome args:** `ZONEEDIT_CHROME_ARGS` (whitespace-split, read at call time) is passed to Chromium.
  The compose file sets `--no-sandbox --disable-dev-shm-usage`. The container sets `shm_size: 512m`.

## Runbook: redeploy after a change to a serving module

**Scope.** Rebuild and restart the NAS container `zoneedit-mcp` with new code. The serving modules are the eight `zoneedit_*.py` files the Dockerfile copies. A docs- or test-only change needs no redeploy. A `Dockerfile` or `deploy/compose.yaml` change needs the rebuild but no version bump (they are not serving modules), so Verify 2 cannot show it took: rely on the image id in Verify 1. A restart cuts any tool call in flight, and a write cut after its final click ends `outcome: "unknown"`: confirm no write is running first, and read the zone after the restart if one was.

**Preflight.**
1. Tests pass on the commit you mean to ship, `__version__` was bumped (the bump gate enforces it), and the tree is clean.
2. Reach the NAS through the `nas-ssh` vault entry, one attempt (the lockout rule in the Isaac safety rules): resolve its `ssh_cmd` inline, never print it. Every remote command needs `PATH=$PATH:/usr/local/bin` for `docker`.
3. Compose names the image `zoneedit-mcp:local` (`deploy/compose.yaml`). Record the running state: `docker inspect -f '{{.Image}}' zoneedit-mcp` and the version a tokenless `initialize` reports.
4. Keep a rollback copy (before step 1 below): `docker tag zoneedit-mcp:local zoneedit-mcp:prev`, and `cp -p` each module you are about to replace to `<module>.prev`.

**Procedure.**
1. Ship each changed module by writing it beside the old one and renaming over it, so a dropped connection never leaves a half file: `cat > .<module>.new && mv -f .<module>.new <module>` in `/volume1/docker/zoneedit-mcp`, with the file on stdin. Compare `sha256sum` on the NAS with the local file.
2. From `/volume1/docker/zoneedit-mcp/deploy` run `docker compose --progress plain --env-file ./site.vars -f compose.yaml up -d --build`. With the Chrome layer cached it finishes in under a minute. If it starts rebuilding the apt or Chrome layer it takes about 55 minutes: let it finish, never kill it.
3. A change to `deploy/zoneedit-mcp.env` or `site.vars` needs the same `up -d`, because compose reads them when it creates the container.

**Verify (all of these before saying it worked).**
1. `docker ps --filter name=zoneedit-mcp` shows `Up`, published on `127.0.0.1:8768` only, and the image id differs from the one recorded in preflight.
2. Read the version back: POST `initialize` to `http://127.0.0.1:8768/mcp` from the NAS (headers `Content-Type: application/json`, `Accept: application/json, text/event-stream`). `serverInfo.version` must equal `__version__` at the shipped commit.
3. A tokenless `tools/call` of `zoneedit_records` returns an `isError` result saying the call was refused and nothing ran.
4. `sha256sum` of all eight modules on the NAS equals the repo at the shipped commit.
5. Through the registered client, call `zoneedit_selftest` once: `login` ok, `panel_total` equal to the live count, `bulk_save_off` true. The container log then shows `tool=zoneedit_selftest principal=fleet`.
6. From the repo on any LAN machine, run `python3 deploy/verify_endpoint.py`. It checks the public mount `https://zoneedit.example.net/mcp` with no bearer. Four lines must read `ok`: bare GET 406, `serverInfo` equal to `__version__`, 9 tools, tokenless call refused. A 404 means the DSM rule is gone and a 421 means a host mismatch. Pass a URL to check another mount.
7. On the machine that holds the main vault, from the repo, run `python3 deploy/zoneedit_admin.py vault status` (the three variables are in [Environment](#environment)): both entries `on_nas` true and `matches` true.

**Failure branches.**
- Any Verify step fails (version, sha256, image id, a tokenless call not refused, a `verify_endpoint.py` line not `ok`, `bulk_save_off` false, a `panel_total` that differs from the panel): do not report done. Roll back, then report the failing step to the operator.
- Build fails: read the last 30 lines of the compose output, fix it in the repo and ship again; never hand-edit files on the NAS.
- Container loops with `refusing to start the HTTP mount`: `zoneedit-mcp.env` lost its `MCP_ADMIN_TOKEN_HASH`. Restore the line from the amt-mcp env file on the NAS (the fleet hash is shared) without printing it, then `up -d`.
- `selftest` returns `login_failed`: stop and do not retry. A repeated failed login can lock the panel account, and the failure latches new logins for 900 s. Run `vault status` (on the machine that holds the main vault, with the three `ZONEEDIT_*` variables from [Environment](#environment)): `on_nas` false means run `vault sync`; `matches` false means the main-vault credential changed, so run `vault sync`. Report to the operator before any further login.
- `selftest` returns `second_factor_required`: the login reached the code page but no usable seed is in the vault (`zoneedit-panel-totp-seed` missing or unreadable on the NAS). Run `vault status`; if the entry is absent, run `vault sync`. Do not retry the login. Report to the operator.
- `selftest` returns `second_factor_rejected`: the one TOTP submit did not pass the code page. Stop and do not retry; the seed may be wrong or the panel may have changed. The server latches new attempts for 900 s. Report to the operator before any further login.
- `selftest` returns `login_latched`: a login or second-factor failure happened in the last 900 s. Nothing reached the panel. Read the cause first with `zoneedit_2fa_status`. Wait out the latch, or clear it with `zoneedit_2fa_latch_clear` only after the operator agrees. A restart also clears it.
- `selftest` or a read returns `RunDeadlineExceeded` or `RunBusy`: the run exceeded 150 s and its browser was killed, or another run held the browser for 170 s. Nothing is a credential failure. Wait a minute and try once. A confirmed write that ends `outcome: "unknown"` needs a zone read before any retry.
- Roll back: `docker tag zoneedit-mcp:prev zoneedit-mcp:local`, restore each module with `mv -f <module>.prev <module>`, then `up -d` without `--build` (compose reuses the re-tagged `zoneedit-mcp:local`). Rerun Verify against the previous commit and image id: the version in Verify 2 and the checksums in Verify 4 are now the previous ones.

**Done.** Verify 1 to 7 all pass, the running version is recorded in the tracker's receipt, and the change is committed (a push still needs the operator's word).

**Update this section when** the Dockerfile COPY list, `deploy/compose.yaml`, the NAS directory layout, the DSM rule or the verification tools change. `tests/test_deploy.py` pins the Dockerfile and compose facts this section relies on.
