"""Deploy-file tests: pure file reads and fakes. No docker, no ssh, no browser, no network."""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

import zoneedit_session as zs

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy"
DOCKERFILE = REPO / "Dockerfile"
DOCKERIGNORE = REPO / ".dockerignore"
COMPOSE = DEPLOY / "compose.yaml"
SITE_EXAMPLE = DEPLOY / "site.vars.example"
ADMIN_PATH = DEPLOY / "zoneedit_admin.py"


def _load_admin():
    spec = importlib.util.spec_from_file_location("zoneedit_admin", ADMIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod      # dataclasses resolves the module by name while it executes
    spec.loader.exec_module(mod)
    return mod


admin = _load_admin()
SSH_ENTRY = "nas-ssh"
CFG = admin.Config(cli="/vault/secrets.py", deploy_dir="/volume1/docker/zoneedit-mcp", ssh_entry=SSH_ENTRY)
VALUES = {key: f"value-for-{key}-7c1e" for key in admin.ALLOWED_KEYS}


def _module_closure(root: str = "zoneedit_server") -> set[str]:
    """Every root-level zoneedit_* module the server imports, transitively, from the import lines."""
    seen: set[str] = set()
    todo = [root]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        text = (REPO / f"{name}.py").read_text()
        todo += re.findall(r"^\s*(?:from|import)\s+(zoneedit_\w+)", text, re.M)
    return {f"{n}.py" for n in seen}


def _copied_modules() -> set[str]:
    copies = [line.split() for line in DOCKERFILE.read_text().splitlines()
              if line.startswith("COPY ") and line.split()[-1] == "./"]
    assert len(copies) == 1, "expected exactly one module COPY line"
    return set(copies[0][1:-1])


def test_dockerfile_copies_exactly_the_modules_the_server_imports():
    closure = _module_closure()
    assert "zoneedit_server.py" in closure and len(closure) >= 7   # non-vacuous
    assert _copied_modules() == closure
    assert "zoneedit_writes.py" in _copied_modules()


def _code_lines(text: str) -> str:
    """The non-comment lines only. A comment that quotes an install command is not the command."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def test_dockerfile_installs_dig_and_chrome_and_runs_as_non_root():
    text = DOCKERFILE.read_text()
    code = _code_lines(text)
    assert "dnsutils" in code
    assert "patchright install --with-deps chrome" in code
    assert re.search(r"^USER zoneedit$", text, re.M)
    assert re.search(r'^CMD \["python", "zoneedit_server.py"\]$', text, re.M)


def test_compose_build_context_is_repo_root():
    assert re.search(r"^\s*context:\s*\.\.\s*$", COMPOSE.read_text(), re.M)


def test_site_example_admin_deploy_dir_is_the_compose_directory():
    """The path vault sync writes into must be the directory compose mounts (`<root>/deploy`)."""
    m = re.search(r"ZONEEDIT_ADMIN_DEPLOY_DIR=(\S+)", SITE_EXAMPLE.read_text())
    assert m is not None
    assert m.group(1).endswith("/deploy")


def test_compose_has_one_service():
    names = re.findall(r"^  ([A-Za-z][\w-]*):\s*$", COMPOSE.read_text(), re.M)
    assert names == ["zoneedit-mcp"]


def test_compose_publishes_only_loopback_and_stays_on_bridge():
    """Pins the CLAUDE.md guardrail 'compose publishes 127.0.0.1:8768 only'. The service is parsed as YAML,
    so every quoting and form counts: quoted, bare (an int), long-form dict, or a second entry. Every
    ports entry must be a string beginning 127.0.0.1:, at least one must exist (a missing ports block
    cannot pass), and the network mode must be bridge exactly."""
    svc = yaml.safe_load(COMPOSE.read_text())["services"]["zoneedit-mcp"]
    ports = svc.get("ports")
    assert isinstance(ports, list) and ports, "ports: must list at least one entry"
    for entry in ports:
        assert isinstance(entry, str) and entry.startswith("127.0.0.1:"), \
            f"publishes outside loopback, or not a plain string: {entry!r}"
    assert svc.get("network_mode") == "bridge"


def test_deploy_files_name_no_secret_value_and_no_token_hash():
    for path in (COMPOSE, SITE_EXAMPLE, DOCKERFILE):
        text = path.read_text()
        assert not re.search(r"[0-9a-fA-F]{64}", text), path.name
        # A placeholder (`MCP_ADMIN_TOKEN_HASH=<...>`) is documentation; any other value is a real hash.
        assert not re.search(r"MCP_ADMIN_TOKEN_HASH=(?!<)\S", text), path.name


def test_dockerignore_excludes_vault_key_and_env_files():
    lines = {ln.strip() for ln in DOCKERIGNORE.read_text().splitlines()
             if ln.strip() and not ln.startswith("#")}
    required = {".git", "tests", "deploy", "__pycache__", "*.md", ".pytest_cache",
                "*.vault", "*.key", "*.env", "site.vars"}
    assert required <= lines


def test_admin_imports_nothing_from_amt_mcp():
    assert re.search(r"^\s*(?:import|from)\s+amt", ADMIN_PATH.read_text(), re.M) is None


class _Runner:
    """Fake for subprocess.run. Answers the vault CLI and the ssh path; records every call."""

    def __init__(self, status_body=None):
        self.calls: list[tuple[list, dict]] = []
        self.status_body = status_body

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if argv[0] == "ssh":
            if "docker exec" in argv[-1]:
                body = self.status_body if self.status_body is not None else \
                    {k: {"on_nas": True, "matches": True} for k in admin.ALLOWED_KEYS}
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(body).encode(), stderr=b"")
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        verb = argv[2]
        if verb == "get":
            key = argv[3]
            if key == SSH_ENTRY:
                out = json.dumps({"ssh_cmd": "ssh -p 22", "user": "op", "host": "nas.example"})
            else:
                out = VALUES[key] + "\n"
            return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
        if verb == "init":
            for name in ("NVAULT_VAULT_PATH", "NVAULT_MASTER_KEY_FILE"):
                Path(kw["env"][name]).write_bytes(b"x")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def test_admin_refuses_a_key_outside_the_two_allowed():
    runner = _Runner()
    with pytest.raises(SystemExit):
        admin.sync(CFG, runner, keys=["zoneedit-panel-username", "nas-ssh"])
    assert runner.calls == []


def test_copy_value_refuses_a_non_allowed_key_by_itself():
    """sync() and copy_value() hold this property redundantly: sync refuses a bad key before
    build_vault reads anything, and copy_value refuses it before its own read. This test calls
    copy_value directly, with no sync in the path, so it goes red when copy_value's guard is removed,
    whether or not sync still refuses."""
    runner = _Runner()
    with pytest.raises(SystemExit):
        admin.copy_value(CFG, "nas-ssh", runner)
    assert runner.calls == []


@pytest.fixture
def admin_env(monkeypatch):
    monkeypatch.setenv("ZONEEDIT_SECRETS_CLI", CFG.cli)
    monkeypatch.setenv("ZONEEDIT_ADMIN_DEPLOY_DIR", CFG.deploy_dir)
    monkeypatch.setenv("ZONEEDIT_ADMIN_SSH_ENTRY", SSH_ENTRY)


U, P, T = admin.ALLOWED_KEYS


def _status_body(user=(True, True), pw=(True, True), totp=(True, True), missing=()):
    """The NAS answer: each key's (on_nas, matches), or absent when listed in ``missing``."""
    body = {}
    for key, (on_nas, matches) in ((U, user), (P, pw), (T, totp)):
        if key not in missing:
            body[key] = {"on_nas": on_nas, "matches": matches}
    return body


@pytest.mark.parametrize("body, rc", [
    (_status_body(), 0),                          # every key on the NAS and matching
    (_status_body(user=(False, False)), 1),       # a key not on the NAS
    (_status_body(pw=(True, False)), 1),          # a key on the NAS with a digest mismatch
    (_status_body(totp=(False, False)), 1),       # the TOTP seed not on the NAS
    (_status_body(missing=(U,)), 1),              # a key absent from the NAS answer
    (_status_body(missing=(P,)), 1),
    (_status_body(missing=(T,)), 1),
])
def test_vault_status_exit_code_follows_every_key(admin_env, capsys, body, rc):
    assert admin.main(["vault", "status"], runner=_Runner(status_body=body)) == rc
    assert "value-for" not in capsys.readouterr().out   # the status output names keys, never values


class _NoContainerRunner(_Runner):
    """A fresh deploy: the zoneedit-mcp container does not exist yet, so every docker exec fails."""

    def __call__(self, argv, **kw):
        if argv[0] == "ssh" and "docker exec" in argv[-1]:
            self.calls.append((list(argv), kw))
            return subprocess.CompletedProcess(argv, 1, stdout=b"",
                                               stderr=b"Error: No such container: zoneedit-mcp")
        return super().__call__(argv, **kw)


def test_vault_sync_never_touches_the_container(admin_env, capsys):
    """sync depends only on the main vault and the NAS deploy directory, never on the container. On a
    fresh deploy the container does not exist, so a docker exec in the sync path would fail and sync
    could never exit 0. The runner fails every docker exec, so putting status back in the sync path
    turns this red."""
    runner = _NoContainerRunner()
    assert admin.main(["vault", "sync"], runner=runner) == 0
    assert json.loads(capsys.readouterr().out) == {"synced": list(admin.ALLOWED_KEYS)}
    assert not any("docker exec" in part for argv, _ in runner.calls for part in argv)


def test_admin_sync_passes_values_by_stdin_never_argv():
    runner = _Runner()
    admin.sync(CFG, runner)
    for argv, _ in runner.calls:
        for value in VALUES.values():
            assert not any(value in part for part in argv)
    sets = [(argv, kw) for argv, kw in runner.calls if argv[0] != "ssh" and argv[2] == "set"]
    assert [argv[3] for argv, _ in sets] == list(admin.ALLOWED_KEYS)
    for argv, kw in sets:
        assert kw["input"] == VALUES[argv[3]] + "\n"


def test_admin_keys_lists_the_two_entries(capsys):
    assert admin.main(["vault", "keys"]) == 0
    assert json.loads(capsys.readouterr().out) == {"keys": list(admin.ALLOWED_KEYS)}


@pytest.fixture
def fake_patchright(monkeypatch):
    calls: list[dict] = []

    class _Context:
        def new_page(self):
            return object()

    class _Browser:
        def new_context(self, **kwargs):
            return _Context()

        def close(self):
            pass

    class _Chromium:
        def launch(self, **kwargs):
            calls.append(kwargs)
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

    class _CM:
        def __enter__(self):
            return _Playwright()

        def __exit__(self, *exc):
            return False

    sync_api = types.ModuleType("patchright.sync_api")
    sync_api.sync_playwright = lambda: _CM()
    monkeypatch.setitem(sys.modules, "patchright", types.ModuleType("patchright"))
    monkeypatch.setitem(sys.modules, "patchright.sync_api", sync_api)
    monkeypatch.setattr(zs, "get_credentials", lambda: ("u", "p"))
    monkeypatch.setattr(zs, "login", lambda page, user, password: None)
    return calls


def test_chrome_args_unset_launches_with_no_args(monkeypatch, fake_patchright):
    monkeypatch.delenv("ZONEEDIT_CHROME_ARGS", raising=False)
    assert zs.run(lambda page: "ok") == "ok"
    assert fake_patchright == [{"channel": "chrome", "headless": True, "args": []}]


def test_chrome_args_set_are_split_on_whitespace(monkeypatch, fake_patchright):
    monkeypatch.setenv("ZONEEDIT_CHROME_ARGS", "  --no-sandbox   --disable-dev-shm-usage ")
    assert zs.run(lambda page: "ok") == "ok"
    assert fake_patchright == [{"channel": "chrome", "headless": True,
                                "args": ["--no-sandbox", "--disable-dev-shm-usage"]}]
