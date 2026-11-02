# zoneedit-mcp

> Guidance for coding agents working in this repository.

ZoneEdit DNS records for the domains of one account, read and changed through the ZoneEdit control panel with a
headless Chrome. Five read tools (`zoneedit_records`, `zoneedit_selftest`, `zoneedit_2fa_status`, `zoneedit_domains`,
`zoneedit_schema`) and four write tools (`zoneedit_record_add`, `zoneedit_record_update`,
`zoneedit_record_delete`, `zoneedit_2fa_latch_clear`); see `README.md` for the map. The operator's guide,
install guide, troubleshooting guide and glossary are in `docs/`: change them in the same commit as any tool,
argument, refusal code, dependency, environment variable or vault entry.

## Guardrails

- **Bearer gate is mandatory and fails closed.** Every tool call is gated in
  `GatedFastMCP.call_tool` (`zoneedit_gate.py`). Refusals are MCP tool errors, never HTTP 401/403.
  Unset or malformed `MCP_ADMIN_TOKEN_HASH` refuses every token. Only an explicit
  `ZONEEDIT_TRANSPORT=stdio` skips the gate. Never pass `auth=` or `token_verifier=` to `FastMCP`,
  and never add a tool outside `GatedFastMCP`.
- **Conformity test reads the live tool list.** `tests/test_conformity.py` checks `list_tools()`; parameters are documented in the schema (`Annotated[..., Field(description=...)]`), not the docstring.
- **Secrets stay in-process.** Panel credentials are read through the vault CLI at call time
  (`zoneedit_vault.py`). A `VaultError` names the vault key only. No credential is a tool
  argument, a returned value, a log line, a file or an exception message.
- **No filled value or Patchright call log in any output.** Patchright errors echo the values they
  filled, so `zoneedit_session.run` keeps only the exception type name and the URL without its
  query string (`SessionError`). Never surface `str(exc)` from a browser error.
- **One login attempt per call.** `login` fills the visible fields once and submits once. No retry
  loop. A repeated failed login can lock the panel account. The second factor is one attempt too.
  The seed and the code are never a tool argument, logged, returned or echoed.
- **Headless only, normal user agent.** `headless=True` and the Chrome user agent in
  `zoneedit_session.USER_AGENT`. Never `HeadlessChrome` in any user agent.
- **Fresh context, no persistent profile.** Each run opens a new browser context and always closes
  the browser. One run at a time (`_LOCK`).
- **Every run has a deadline.** `run` executes on a worker thread: `RUN_DEADLINE_S` 150, `LOCK_WAIT_S` 170
  (`RunBusy`), `KILL_GRACE_S` 5. At the deadline the run's browser processes are killed and
  `RunDeadlineExceeded` is raised, never a credential failure. A confirmed write cut by it returns
  `outcome: unknown`. The user agent comes from the installed Chrome (`user_agent_for`).
- **The second-factor tools return names, counts and seconds only.** `zoneedit_2fa_status` never logs in
  and never opens a browser. `zoneedit_2fa_latch_clear` previews unless `confirmed=true` and touches no
  panel. A password-only login never reads the seed. A password-only login must keep working.
- **`tests/test_clickpaths.py`, `test_schema_dom.py` and `test_dynamic_writes_dom.py` start a real Chrome**, network off, synthetic pages
  only, and no test may reach the Confirm button or the zone-level save.
- **A `tfa` page is answered in process, once.** When the login lands on a URL containing `tfa`, the
  login answers a TOTP token itself from the vault entry `zoneedit-panel-totp-seed` (one attempt,
  never retried). A rejected token or a failed login blocks new attempts for 900 s (`LoginLatched`)
  without touching the panel. A missing seed keeps the old stop-and-report (`second_factor_required`).
  The code page was met and passed live on 2026-11-02 (the selftest reported `second_factor: answered`).
- **Parsing is pure.** `zoneedit_panel.py` takes saved HTML and never touches a browser or network.
  Keep Patchright imports inside functions in `zoneedit_session.py` only.
- **Nothing about the account is built in.** The domain list, record types, form fields, option lists, TTL
  labels, settings and name servers are read from the panel on each call; only the login is configured.
  A domain argument is checked against the account's list before it reaches a URL. `tests/test_no_zone_in_code.py`
  keeps the zone name out of the serving modules.
- **Writes are planned first and never replace.** `zoneedit_writes.plan_write` is pure and decides
  every refusal before any click, from the type's live schema (`schema_open`). Add may add a further row
  of a host and type that exists, and refuses any CNAME conflict. A panel that replaces instead is caught by
  the replace stop and by the add verification, which fails when any other row vanished. Update and delete act only on a row read in the
  same call, matched by exact `expect_content` and/or `expect_hash` (no normalising, no wildcard). Apex A,
  NS, SOA and DYN are written like any record: the guard is the preview default, the `confirmed` write
  guard, the annotations and the warning in the tool text, never a refusal by type or host. A disabled form field accepts only
  the panel's own default.
- **Preview by default.** A write tool changes nothing unless `confirmed=True`. A record write's preview
  logs in and reads the panel only. The latch clear's preview does not log in. Pagination clicks during a
  read are not writes.
- **Never confirm a replace.** A visible Confirm button or a shown replace warning stops the run
  (`replace_prompt_shown`). No code path clicks Confirm or the zone-level save.
- **The panel re-read decides `ok`.** After a confirmed write every page is re-read. DNS read-back
  uses the system `dig` (`/usr/bin/dig` on macOS), is informative only, and never changes `ok`.
- **No version since 1.1.1 has a confirmed live write of any type.** Add and delete for TXT and CNAME were proven live
  on 2026-11-01, on version 1.1.1. The write path was rebuilt since (schema read, generic fill, row-set
  verification), so that proof does not cover it. Write PREVIEWS of ten types planned correctly against the
  live schema on 2026-11-02. The first confirmed write needs one operator-approved throwaway record, and it
  will show whether other rows keep their `hash` across a write, which the new verification assumes. Nothing in
  the suite touches the panel or DNS.
- **Tool listing is open, tool calls are gated.** `initialize` and `tools/list` need no bearer and return
  names and descriptions only. The gate sits in the tool-dispatch wrapper, so no tool runs and the panel
  is never touched without the bearer.
- **Tools declare `title` (prefixed `ZoneEdit `) and `readOnlyHint`.** The live-server test checks
  both.
- **Bulk-save state is a live checked property.** Read `#editor_bulk_save_mode` with `is_checked()`; exactly one unchecked switch, else refuse. Never the static `value` attribute.
- **A row shown queued or revoked is not published.** `pending` rows never verify an add, update or delete.
- **A failure after the final Save or Delete click returns `outcome: unknown`.** The caller must read the zone before retrying; it is never a refusal.
- **The DNS page has two pagination navs with identical links.** Always click the first visible page link.
- **Deploy files hold no secret and publish loopback only.** `deploy/` and `Dockerfile` carry no secret
  value or token hash; compose publishes `127.0.0.1:8768` only. The vault sync copies only the three
  entries (two panel credentials and the TOTP seed). Deploy steps are in `README.md` (Deploy section).
- **Semver, bumped by hand with every serving change.** `__version__` in `zoneedit_server.py` is the version of record, equal to `pyproject.toml` and reported by `initialize`. `hooks/version_bump_gate.py` (install with `--install`) blocks a commit that stages a serving module without a bump. Commit subjects end with the version. After a deploy, read `serverInfo.version` back from the container. Details in `README.md` (Versioning); the fleet policy is KB `isaac-mcp-versioning-policy`.
