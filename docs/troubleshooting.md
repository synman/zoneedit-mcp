# Troubleshooting

Find the symptom, read the cause, take the action. For deploy faults see the README runbook, which has its own
failure branches. Terms are in the [glossary](glossary.md).

**One rule first.** After any login failure, **stop and do not retry.** The server makes one login attempt per
call, and a repeated failed login can lock the panel account. Report to the operator before another login.

## Refused before anything runs

| Symptom | Cause | Action |
|---------|-------|--------|
| Tool error "this call requires the mcp-admin-token bearer header ... refused and nothing ran" | The call had no valid bearer. | Use a client that sends the fleet token. Nothing ran. |
| Server exits with code 2, "refusing to start the HTTP mount" | `MCP_ADMIN_TOKEN_HASH` is unset or not 64 hex characters. | Set it to the SHA-256 hex of the fleet token. Never the token. |
| Tool error `VaultError` | A vault entry is missing, empty, unreadable, or `ZONEEDIT_SECRETS_CLI` is unset. | Check the three entries (`zoneedit-panel-username`, `zoneedit-panel-password`, `zoneedit-panel-totp-seed`) and the CLI path. See the README runbook for `vault status`. |

## Login and second factor (`zoneedit_selftest` or any call)

| `error_type` | Cause | Action |
|--------------|-------|--------|
| `login_failed` | The panel did not accept the login. | Stop. Check the vault credential against the panel by hand. Report to the operator before any further login. |
| `second_factor_required` | The login reached the code page and no usable seed is in the vault. | Add or repair `zoneedit-panel-totp-seed`. Do not retry the login. |
| `second_factor_rejected` | The one code submitted was not accepted. | Stop. The seed may be wrong, the clock of the machine running the server may be off, or the panel may have changed. Check the seed with the install guide section 2a, step 3, and the clock with `date -u +%s`. Report to the operator. |
| `login_latched` | A login or code failure happened in the last 900 s. Nothing reached the panel. | Read the cause with `zoneedit_2fa_status`. Wait it out, or clear it with `zoneedit_2fa_latch_clear` only after the operator agrees. A restart also clears it. |

`zoneedit_2fa_status` shows `latch_seconds_left`, `last_second_factor` and whether the seed is present, by name
only. It never logs in.

## Slow or stuck runs

| Symptom | Cause | Action |
|---------|-------|--------|
| `RunDeadlineExceeded` | A run took over 150 s and its browser was killed. It is never a credential failure. | Wait a minute and try once. |
| `RunBusy` | Another run held the one browser for 170 s. | Wait and try once. |
| `zoneedit_schema` is slow | Reading all 31 types takes about 65 s. | Pass `record_type` to read one type in a few seconds. |

## Reads

| Symptom | Cause | Action |
|---------|-------|--------|
| `refused: domain_required` | The account has several domains and none was named. | Pass `domain`, from the `domains` list in the reply. |
| `refused: unknown_domain` or `bad_domain` | The name is not on the account's list, or is not a valid name. | Take it from `zoneedit_domains`. |
| `complete: false` or a `warning` | Not every page or row was read. | Read again. Zero records read is not proof the zone is empty. |
| `unknown_record_type` from `zoneedit_schema` | The type is not on the add form. | Use a name from the `types` list in the reply. |
| `unsettled` types in the schema | A type's form did not finish loading. | Read that type again by itself. |

## Writes

A refusal means nothing was changed.

| Refusal | Cause | Action |
|---------|-------|--------|
| `bad_type` | The type is not offered by the live form. | Take the type from `zoneedit_schema`. |
| `bad_host` | The label is not a valid host name. It must be bare, never the domain's own name. | Use `www`, or `@` for the apex. |
| `empty_content`, `missing_field`, `bad_field`, `unknown_field`, `bad_option`, `bad_ttl`, `bad_prio`, `bad_caa`, `field_disabled` | The input does not fit the type's form. | Read the field list from `zoneedit_schema`. A disabled field takes only the panel's own default. |
| `cname_conflict` | A `CNAME` cannot share a host with another record. | Pick another host, or remove the other record first. |
| `not_found`, `content_mismatch`, `ambiguous`, `bad_hash` | The row to change was not found, differs, matches twice, or the hash is unknown. | Read the row with `zoneedit_records`. Name it by `expect_hash`. |
| `no_change` | The update would leave the row as it is. | Nothing to do. |
| `incomplete_read` | The pre-write read did not cover the whole zone. | Read again. The tool will not plan from a partial zone. |
| `bulk_save_on_or_unknown` | The editor's bulk save mode is on or could not be read. | Switch it off in the panel, then try again. |
| `schema_unavailable` | The type's form did not settle. | Try again. If it repeats, read the schema for that type. |
| `step_failed` (with `step`) | A page step failed before the final click. | Nothing was saved. Read the zone, then try once. |
| `replace_prompt_shown` | The panel asked to confirm a replace. | Nothing was saved. The tool never clicks Confirm. Do it by hand if wanted. |

| Outcome | Meaning | Action |
|---------|---------|--------|
| `outcome: "unknown"` | The failure came after the final Save or Delete click. | **Read the zone before any retry.** The change may have landed. |
| `ok: false` with `differences` | The re-read did not show exactly the change (for example `another row vanished`). | Read the zone and report the differences. |
| `dns_readback` is `{"error": "dig_unavailable"}` | `dig` is not installed. | Harmless. The write is still verified by the panel re-read. |
| `dns_matches` false | A name server did not show the change yet. | Propagation can take time. Check again later. It never changes `ok`. |

## Tests

| Symptom | Cause | Action |
|---------|-------|--------|
| Real-Chrome tests are skipped | Chrome could not launch. | Install Chrome stable, or use the fast run in the README that leaves those three files out. |
| A test fails after a docs-only change | A test pins a Dockerfile, compose or version fact. | Read the failing assertion. `tests/test_deploy.py` and `tests/test_version.py` pin those facts. |

**Update this guide when** a refusal code, an `error_type`, a deadline or a latch time changes. The codes are
in `zoneedit_writes.py`, `zoneedit_tools.py` and `zoneedit_session.py`.
