# zoneedit-mcp: streamable-HTTP MCP server with a headless Chrome for the ZoneEdit control panel.
# Built from the repository root by deploy/compose.yaml (build context ..). The base image is pinned by
# tag; the Python packages are pinned to the versions the code was developed against. No secret is
# baked in or defaulted: the bearer hash comes from the env file and the panel credentials from the
# dedicated vault, both supplied at run time.
FROM python:3.12.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ZONEEDIT_BIND_HOST=0.0.0.0 \
    ZONEEDIT_PORT=8768

# The DNS lookup binary that zoneedit_writes.dns_readback calls is provided by the bind utilities package.
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/*

# cryptography is for the mounted node-vault-mcp secrets.py, which zoneedit_vault runs as a child.
# The patchright chrome installer places Google Chrome stable system-wide; zoneedit_session launches
# channel="chrome" against it. The apt lists are removed in the same layer.
RUN pip install --no-cache-dir "mcp==1.26.0" "patchright==1.64.3" "cryptography==46.0.3" \
    && patchright install --with-deps chrome \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zoneedit

WORKDIR /app
COPY zoneedit_server.py zoneedit_gate.py zoneedit_vault.py zoneedit_totp.py zoneedit_panel.py zoneedit_session.py zoneedit_tools.py zoneedit_writes.py ./

USER zoneedit
EXPOSE 8768

CMD ["python", "zoneedit_server.py"]
