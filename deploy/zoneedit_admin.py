#!/usr/bin/env python3
"""Manage the zoneedit-mcp dedicated vault on its Docker host: the two panel credentials and the TOTP seed.

    zoneedit_admin.py vault keys     the entries the server reads (fixed: the two panel credentials and the TOTP seed)
    zoneedit_admin.py vault status   per entry: on the NAS, and matching the main vault
    zoneedit_admin.py vault sync     rebuild the NAS dedicated vault from the main vault (names only out)

Sync depends only on the main vault and the NAS deploy directory. It never touches the container, which
does not exist until compose has started it; run `vault status` after the container starts.

Run on the operator's machine, which holds the main vault. Configuration (environment, all required):

    ZONEEDIT_SECRETS_CLI        the main vault's secrets.py
    ZONEEDIT_ADMIN_DEPLOY_DIR   the deploy directory on the host (holds vault/ and the compose file)
    ZONEEDIT_ADMIN_SSH_ENTRY    the main-vault entry holding the host's ssh_cmd, user and host

Credentials: sync reads only the three entries in ALLOWED_KEYS. No value is printed, logged, put in argv or
left in a file. Values reach secrets.py over stdin; the NAS side answers with a match yes/no computed from
SHA-256 digests. Output names keys and reports ok or fail only.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ALLOWED_KEYS = ("zoneedit-panel-username", "zoneedit-panel-password", "zoneedit-panel-totp-seed")
CONTAINER = "zoneedit-mcp"
VAULT_FILES = ("zoneedit-mcp.vault", "zoneedit-mcp.key")
EXPIRES = "2035-01-01"
NOTES = "zoneedit-mcp dedicated vault copy (deploy/zoneedit_admin.py vault sync)"
NAS_CLI = "/opt/node-vault-mcp/services/secrets.py"   # inside the container; read from its own env

Runner = Callable[..., subprocess.CompletedProcess]

# Runs inside the container. Reads "<key>\t<sha256 or ->" lines on stdin and answers per key with
# whether the container's vault holds a value and whether that value's SHA-256 equals the given one.
CHECK = r"""
import hashlib, json, os, subprocess, sys
cli = os.environ["ZONEEDIT_SECRETS_CLI"]
out = {}
for line in sys.stdin.read().splitlines():
    key, want = line.split("\t")
    r = subprocess.run([sys.executable, cli, "get", key], capture_output=True, text=True)
    got = r.stdout.rstrip("\n") if r.returncode == 0 else ""
    on_nas = bool(got.strip())
    out[key] = {"on_nas": on_nas, "matches": on_nas and hashlib.sha256(got.encode()).hexdigest() == want}
print(json.dumps(out))
"""


@dataclass(frozen=True)
class Config:
    cli: str
    deploy_dir: str
    ssh_entry: str


def config_from_env() -> Config:
    values = {}
    for name in ("ZONEEDIT_SECRETS_CLI", "ZONEEDIT_ADMIN_DEPLOY_DIR", "ZONEEDIT_ADMIN_SSH_ENTRY"):
        value = os.environ.get(name, "").strip()
        if not value:
            raise SystemExit(f"{name} is not set")
        values[name] = value
    return Config(values["ZONEEDIT_SECRETS_CLI"], values["ZONEEDIT_ADMIN_DEPLOY_DIR"].rstrip("/"),
                  values["ZONEEDIT_ADMIN_SSH_ENTRY"])


def refuse_unless_allowed(keys) -> None:
    refused = [k for k in keys if k not in ALLOWED_KEYS]
    if refused:
        raise SystemExit("refusing key(s) outside the allowed set: " + ", ".join(refused))


def read_main(cfg: Config, key: str, runner: Runner) -> str | None:
    """A main-vault value, or None. Nothing here prints it; the caller decides what it is used for."""
    r = runner([sys.executable, cfg.cli, "get", key], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout.rstrip("\n")


def copy_value(cfg: Config, key: str, runner: Runner) -> str:
    """The value of one allowed key from the main vault. Any other key is refused before a read."""
    refuse_unless_allowed([key])
    value = read_main(cfg, key, runner)
    if value is None:
        raise SystemExit(f"main vault has no value for {key}; nothing changed")
    return value


def ssh_argv(cfg: Config, remote: str, runner: Runner) -> list[str]:
    raw = read_main(cfg, cfg.ssh_entry, runner)
    if raw is None:
        raise SystemExit(f"vault entry {cfg.ssh_entry} missing")
    entry = json.loads(raw)
    return [*shlex.split(entry["ssh_cmd"]), "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
            f"{entry['user']}@{entry['host']}", remote]


def nas(cfg: Config, remote: str, data: bytes, runner: Runner) -> str:
    r = runner(ssh_argv(cfg, remote, runner), input=data, capture_output=True)
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace").strip()[-200:]
        raise SystemExit(f"NAS command failed (rc {r.returncode}): {err}")
    return r.stdout.decode(errors="replace")


def build_vault(cfg: Config, directory: Path, runner: Runner, keys=ALLOWED_KEYS) -> None:
    """Initialise a dedicated vault in ``directory`` and set each key from the main vault via stdin."""
    env = {k: v for k, v in os.environ.items() if k != "SECRETS_KEY"}
    env.update(NVAULT_VAULT_PATH=str(directory / VAULT_FILES[0]),
               NVAULT_MASTER_KEY_FILE=str(directory / VAULT_FILES[1]),
               NVAULT_KEYCHAIN_SERVICE="zoneedit-mcp-dedicated-vault-unused")
    if runner([sys.executable, cfg.cli, "init"], env=env, capture_output=True, text=True).returncode != 0:
        raise SystemExit("dedicated vault init failed")
    for key in keys:
        value = copy_value(cfg, key, runner)
        r = runner([sys.executable, cfg.cli, "set", key, "--expires", EXPIRES, "--notes", NOTES],
                   env=env, input=value + "\n", capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"dedicated vault set {key} failed (rc {r.returncode})")


def sync(cfg: Config, runner: Runner, keys=ALLOWED_KEYS) -> None:
    """Rebuild the NAS vault from the main vault. The vault is built in a private temp directory and
    streamed over ssh; each file is renamed over the old one, which stays as .prev-<name>."""
    refuse_unless_allowed(keys)
    with tempfile.TemporaryDirectory(prefix="zoneedit-nas-vault-") as tmp:
        d = Path(tmp)
        os.chmod(d, 0o700)
        build_vault(cfg, d, runner, keys)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name in VAULT_FILES:
                info = tar.gettarinfo(str(d / name), arcname=f".new-{name}")
                info.mode = 0o600
                with open(d / name, "rb") as fh:
                    tar.addfile(info, fh)
    vault_dir = shlex.quote(f"{cfg.deploy_dir}/vault")
    steps = [f"mkdir -p {vault_dir}", f"chmod 700 {vault_dir}", f"cd {vault_dir}", "tar -x -f -"]
    for name in VAULT_FILES:
        steps += [f"if [ -f {name} ]; then cp -p {name} .prev-{name}; fi",
                  f"chmod 600 .new-{name}", f"mv -f .new-{name} {name}"]
    steps.append("chmod 700 .")
    nas(cfg, "set -e; " + "; ".join(steps), buf.getvalue(), runner)


def status(cfg: Config, runner: Runner, keys=ALLOWED_KEYS) -> dict:
    """Per key: ``on_nas`` and ``matches`` (the NAS value's SHA-256 equals the main vault's)."""
    refuse_unless_allowed(keys)
    lines = []
    for key in keys:
        value = read_main(cfg, key, runner)
        digest = hashlib.sha256(value.encode()).hexdigest() if value is not None else "-"
        lines.append(f"{key}\t{digest}")
    remote = f"PATH=/usr/local/bin:$PATH docker exec -i {CONTAINER} python3 -c " + shlex.quote(CHECK)
    out = nas(cfg, remote, ("\n".join(lines) + "\n").encode(), runner)
    try:
        return json.loads(out)
    except ValueError:
        raise SystemExit("the NAS status answer was unreadable; nothing changed") from None


def status_ok(out: dict, keys=ALLOWED_KEYS) -> bool:
    return all(k in out and out[k]["on_nas"] and out[k]["matches"] for k in keys)


def main(argv: list[str] | None = None, runner: Runner = subprocess.run) -> int:
    parser = argparse.ArgumentParser(prog="zoneedit_admin.py", description=__doc__.split("\n\n")[0])
    vault_p = parser.add_subparsers(dest="group", required=True).add_parser("vault").add_subparsers(
        dest="action", required=True)
    for name in ("keys", "status", "sync"):
        vault_p.add_parser(name)
    a = parser.parse_args(argv)
    if a.action == "keys":
        print(json.dumps({"keys": list(ALLOWED_KEYS)}))
        return 0
    cfg = config_from_env()
    if a.action == "sync":
        sync(cfg, runner)
        print(json.dumps({"synced": list(ALLOWED_KEYS)}))
        return 0
    out = status(cfg, runner)
    print(json.dumps({"vault": out}))
    return 0 if status_ok(out) else 1


if __name__ == "__main__":
    sys.exit(main())
