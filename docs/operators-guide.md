# Operator's guide

How to read and change DNS records with the `zoneedit-mcp` tools. All examples use the invented domain
`example.net`. Terms are in the [glossary](glossary.md). Faults are in [troubleshooting](troubleshooting.md).

**Scope.** This guide is for the person or agent who asks for a record to be read, added, changed or deleted.
Installing and deploying the server is in the [install guide](install-guide.md) and the README runbook.

## What the tools do

| Need | Tool | Changes anything? |
|------|------|-------------------|
| Which domains does the account hold? | `zoneedit_domains` | No |
| Which record types and form fields exist? | `zoneedit_schema` | No |
| Which records exist? | `zoneedit_records` | No |
| Does the login still work? | `zoneedit_selftest` | No |
| Is the login blocked, and for how long? | `zoneedit_2fa_status` | No |
| Add, change or delete one record | `zoneedit_record_add`, `zoneedit_record_update`, `zoneedit_record_delete` | Only with `confirmed=true` |
| Unblock logins after a failure was fixed | `zoneedit_2fa_latch_clear` | Only with `confirmed=true`, and never DNS. Without it, it only reports the seconds left. |

Every tool call over HTTP needs the shared admin bearer token. A registered client sends it for you.
Only the panel login is configured. Domains, record types, form fields and name servers are read from the
account on every call, so nothing here is specific to one zone.

## The safe change routine

Run these in order. Steps 1 to 4 and 6 change nothing. Every call that reads the panel, a preview included,
logs in once. Do not loop calls, and do not retry after a login failure.

1. **Find the domain.** `zoneedit_domains {}`. With one domain the `domain` argument may stay empty. With
   several, name one or the call is refused with `domain_required`.
2. **Read what exists.** `zoneedit_records {"domain": "example.net", "host": "www"}`. Check `complete` is true
   and `pending` is false on the rows you care about. A row with `pending: true` is queued or revoked and is
   not published. Zero records read is not proof the zone has none.
3. **Learn the form.** `zoneedit_schema {"domain": "example.net", "record_type": "TXT"}` lists the fields, which
   are required, which are disabled and the values a select accepts. Skip it for a plain `A` or `CNAME`.
4. **Preview.** Call the write tool without `confirmed`. It logs in, reads the panel, opens the add form to read the type's fields, saves nothing and
   returns `before` and `after`. A delete preview opens no form.
   ```
   zoneedit_record_add {"domain": "example.net", "type": "TXT", "host": "www", "content": "v=spf1 -all"}
   ```
5. **Get the operator's word on that exact preview.** Only then repeat the same call with `"confirmed": true`.
   The approval covers that one change and nothing else.
6. **Read the result.** `ok: true` means the panel re-read showed the change. `panel_verified` and `verified`
   carry the same value, and `differences` is absent when they are true. `dns_readback` and `dns_matches` are extra evidence and never change `ok`.
7. **Read the zone again** with `zoneedit_records` if anything looked odd.

## Changing or deleting a row

Update and delete act only on a row read in the same call. Name it by exact current content, by `hash` from
`zoneedit_records`, or both. There is no normalising and no wildcard.

```
zoneedit_record_update {"domain": "example.net", "type": "A", "host": "www",
                        "expect_content": "192.0.2.10", "new_content": "192.0.2.20"}
zoneedit_record_delete {"domain": "example.net", "type": "TXT", "host": "www", "expect_hash": "<hash from records>"}
```

- `content_mismatch` means the row's content differs from what you gave. Read the row again.
- `ambiguous` means two rows match. Name one by `expect_hash`.
- `no_change` means the update would leave the row as it is.

## Adding a second row

The add tool is built to add a further row beside any row of the same host and type, such as a second `MX` or
`TXT`. **This is not proven live**: see "What is proven" below. The preview lists the rows already there as
`before`. If the panel replaces a row instead of adding, the tool stops at the panel's Confirm prompt
(`replace_prompt_shown`) or the re-read fails with `another row vanished`. Neither is reported as done.

## Records that need extra care

The tools do not refuse by record type or host. The guard is the preview, the `confirmed` flag and your judgment.
Preview first and confirm only on the operator's word for these:

- **The apex `A` and `NS` and `SOA` rows.** They answer for the whole zone. A wrong write can take every
  record offline.
- **`DYN` rows.** An update client keeps them fresh, so a hand edit can be overwritten.
- **`CNAME`.** A `CNAME` cannot sit beside any other record at the same host. Both directions are refused as
  `cname_conflict`.

## When the result is not a clean `ok`

| You see | Meaning | Do |
|---------|---------|----|
| `ok: false` with `refused: <code>` | Nothing was changed. | Fix the input named by the code, see [troubleshooting](troubleshooting.md). |
| `outcome: "unknown"` | The failure came after the final Save or Delete click. The change may or may not have landed. | Read the zone with `zoneedit_records` before any retry. Never retry blind. |
| `verified: false` or `differences` | The panel re-read did not show exactly the change. | Read the zone. Report the differences to the operator. |
| `replace_prompt_shown` | The panel wanted to confirm a replace. The tool never clicks Confirm. | Nothing changed. Do the replace by hand in the panel if it is wanted. |

## The second factor

When the panel asks for a code, the server answers it from the TOTP seed in the vault. No Google app or account is
involved, because the code is plain RFC 6238. Check it with `zoneedit_2fa_status` (`seed` should read `present`) and
one `zoneedit_selftest` (`second_factor` of `answered`). If the panel account is re-enrolled, the seed changes: store the
new one, sync it to the server's vault, and run one selftest before any change. Enrollment, the seed check and the clock
check are in the [install guide](install-guide.md#2a-set-up-the-second-factor-totp). A rejected code latches logins for
900 seconds, so read [troubleshooting](troubleshooting.md) before trying again.

## What the tools never do

- Replace a record. No code path clicks the panel's Confirm button or the zone-level save.
- Return, log or accept a credential, a second-factor seed or a code.
- Retry a login. A repeated failed login can lock the panel account.
- Touch DNS outside the account's own panel.

## What is proven

Read this before relying on a write. The sections of the README under "Where it runs" hold the dated record.
No version since 1.1.1 has a confirmed live write of any type. The first confirmed write needs one
operator-approved throwaway record. It will also show whether a further row beside an existing host and type
is added or replaced, and whether other rows keep their `hash`.

**Update this guide when** a tool, an argument, a refusal code or the safe routine changes. The tool text in
`zoneedit_server.py` and the conformity test `tests/test_conformity.py` are the source of the tool facts here.
