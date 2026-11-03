# Install guide

Three ways to run `zoneedit-mcp`: a local stdio process, a local HTTP process, or the Docker deployment on the
NAS. The Docker deployment and the redeploy runbook are in the [README](../README.md#deploy). This guide covers
what they all need and the two local runs. Terms are in the [glossary](glossary.md).

## Prerequisites

- Python 3.11 or newer.
- Google Chrome stable. Patchright drives it headless (`channel="chrome"`).
- The Python packages `mcp` (1.26 or newer, below 2) and `patchright`. The image pins `mcp==1.26.0` and
  `patchright==1.64.3`.
- A vault CLI script. The server runs `python <cli> get <entry>` and reads the value from stdout, raw or as
  JSON. Any script with that contract works, and the author's own vault CLI is not published.
- `dig` from the DNS utilities, optional. Without it a write still verifies and `dns_readback` reports
  `{"error": "dig_unavailable"}`.
- A ZoneEdit account. If it asks for a second factor, a TOTP seed (section 2a). No Google app is needed.

## 1. Get the code and the packages

```
cd <path to this repo>
python3 -m venv .venv && . .venv/bin/activate
pip install "mcp>=1.26,<2" patchright
patchright install chrome
```

`pip install -e .` also works and adds the `zoneedit-mcp` command.

## 2. Store the panel credentials

Three vault entries hold everything the server needs. The names are fixed:

| Vault entry | Holds |
|-------------|-------|
| `zoneedit-panel-username` | The panel login name. |
| `zoneedit-panel-password` | The panel password. |
| `zoneedit-panel-totp-seed` | The TOTP seed, raw text or JSON with a `seed` or `value` field. Needed only when the panel asks for a second factor. Section 2a. |

**Store them yourself, in a separate terminal, with the vault CLI's `set` command.** Never type a value into an
agent session, because the transcript is kept in plaintext. The shape, once per entry:

```
<path to secrets.py> set zoneedit-panel-username --value '<value>' --expires <YYYY-MM-DD>
```

The server reads them in-process at call time and never returns, logs or echoes them.

## 2a. Set up the second factor (TOTP)

Skip this if the panel asks for a password only. When it asks for a code, the server answers it itself and needs
one thing: the **TOTP seed**. **No Google app and no Google account is involved.** The codes are plain RFC 6238
(HMAC-SHA1, 30 second step, six digits), computed in `zoneedit_totp.py` with the Python standard library.
"Google Authenticator" is only the name of a phone app that does the same sum. Any seed that app can hold, the
server can use, and the seed is the whole second factor.

1. **Enroll in the panel.** In the ZoneEdit control panel open the Authentication Method page and choose an
   Authenticator app. The panel shows a QR code and a one-time **recovery code**. Keep the recovery code in your
   own vault and nowhere else. Using it turns two-factor off.
2. **Read the seed out of the QR.** The QR holds an `otpauth://totp/...?secret=<BASE32>` link. The base32 text
   after `secret=` is the seed. Decode the QR offline in your own terminal with any QR decoder. If the panel
   also offers the key as text, use that. Never paste or photograph the QR into an agent session, because it is
   the whole second factor and the transcript is kept in plaintext.
3. **Check the seed before you store it.** From the repo, in your own terminal, with a seed you can compare against
   any authenticator app set up from the same QR:

   ```
   python3 -c "import getpass,sys,time; sys.path.insert(0,'.'); from zoneedit_totp import totp; print(totp(getpass.getpass('seed: '), time.time()))"
   ```

   The six digits must match the app's within the same 30 seconds. The seed may be typed with spaces, hyphens or
   lower case, and the padding may be missing. The RFC 6238 test seed is the text `12345678901234567890` in base32. It gives `287082` at
   epoch second 59, which `tests/test_totp.py` pins. That checks the install without touching your account.
4. **Store it** in your own terminal. Omit `--value` so the vault CLI reads the seed from the prompt or stdin:

   ```
   <path to secrets.py> set zoneedit-panel-totp-seed --expires <YYYY-MM-DD>
   ```

   For the NAS container, copy the entry to its vault with the deploy `vault sync` step in the README Deploy
   section. The recovery code is deliberately not in that sync.
5. **Check the clock.** The code depends on the clock of the machine that runs the server, which is the container
   on the NAS. Compare `date -u +%s` there with a trusted clock. A clock that is off by a step or more produces a
   wrong code, and the panel answers `second_factor_rejected`.
6. **Prove it end to end** with the checks in section 4: `zoneedit_2fa_status` shows `seed` as `present`, and one
   `zoneedit_selftest` shows `second_factor` as `answered`.

What the server does at the code page: one password submit, then at most one code, never retried. A code
computed in the last 5 seconds of its step waits for the next step. The same step's code is never submitted twice
by one process. A rejected code or a failed login latches new logins for 900 seconds. If you re-enroll, the seed
changes: store the new one, sync it, and run one selftest.

## 3a. Run as a local stdio process

No bearer gate applies, because the process boundary is the control.

```
ZONEEDIT_SECRETS_CLI=<path to secrets.py> python3 zoneedit_server.py --transport stdio
```

Register it in a client's `.mcp.json` as a stdio server with the same command and environment.

## 3b. Run as a local HTTP server

```
MCP_ADMIN_TOKEN_HASH=<sha256 hex of the token> ZONEEDIT_SECRETS_CLI=<path to secrets.py> \
  python3 zoneedit_server.py
```

It binds `127.0.0.1:8768`. With `MCP_ADMIN_TOKEN_HASH` unset or not a 64-character hex digest the server refuses
to start and exits with code 2. Only the hash is configured, never the token. Register it as an `http` server at
`http://127.0.0.1:8768/mcp` with a header helper that sends the bearer. The other variables are in the README
under [Environment](../README.md#environment).

## 3c. Run on the NAS in Docker

Follow the README [Deploy](../README.md#deploy) section for the layout, `site.vars`, the env file and the vault
sync. Redeploys follow the README runbook. The first Chrome layer build takes about 55 minutes.

## 4. Check the install

1. Call `zoneedit_2fa_status`. It needs no browser and no login. `seed` should read `present` when a second
   factor is expected.
2. Call `zoneedit_selftest` once. A good result has `login` ok, a `panel_total`, `bulk_save_off` true and
   `second_factor` of `answered` or `not_asked`.
3. Call `zoneedit_domains` and `zoneedit_records`. `complete` should be true.
4. Over HTTP also check the gate: a `tools/call` of `zoneedit_records` without the bearer must be refused with
   "the call was refused and nothing ran". Do not use `tools/list` for this, because it needs no token.

If `zoneedit_selftest` fails, **do not call it again.** Read [troubleshooting](troubleshooting.md) first, because
a repeated failed login can lock the panel account.

## 5. Run the tests

```
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -p no:xdist -q
```

The tests need no network and no vault. See the README [Running](../README.md#running) section for the fast
offline run.

**Update this guide when** the dependencies in `pyproject.toml`, the `Dockerfile`, the vault entry names, the
start command or the environment variables change.
