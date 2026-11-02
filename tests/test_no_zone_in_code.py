"""The zone stays out of the code. The account supplies the domain, the name servers and every other zone
fact on each call, so no serving module may name a zone or hold the DNS editor URL constant.

The scan list is the module list the Dockerfile COPY line ships, as tests/test_deploy.py reads it.
deploy/verify_endpoint.py is deployment configuration and is not scanned.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "Dockerfile"
FORBIDDEN = (re.compile(r"DNS_URL"), re.compile(r"LOGIN=[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"))


def _serving_modules() -> list[Path]:
    copies = [line for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
              if line.startswith("COPY ") and line.split()[-1] == "./"]
    assert len(copies) == 1, "expected exactly one module COPY line"
    return [REPO / name for name in copies[0].split()[1:-1] if name.endswith(".py")]


def _forbidden_in(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [rx.pattern for rx in FORBIDDEN if rx.search(text)]


def test_the_eight_serving_modules_name_no_zone_and_no_dns_url():
    modules = _serving_modules()
    assert len(modules) == 8, modules
    assert all(path.exists() for path in modules)
    hits = {path.name: _forbidden_in(path) for path in modules}
    assert {name: found for name, found in hits.items() if found} == {}


def test_positive_control_detects_planted_zone_text_and_passes_clean_text(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text('DNS_URL = "https://cp.zoneedit.com/index.php?LOGIN=zone.example"\n', encoding="utf-8")
    assert _forbidden_in(planted) == [rx.pattern for rx in FORBIDDEN]
    clean = tmp_path / "clean.py"
    clean.write_text("DOMAIN_NAME = 'example.com'\n", encoding="utf-8")
    assert _forbidden_in(clean) == []
