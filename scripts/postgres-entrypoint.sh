#!/bin/bash
# ---------------------------------------------------------------------------
# Root entrypoint wrapper for the Postgres container.
#
# Postgres refuses to start if its TLS private key is group/world-readable or
# isn't owned by the postgres user. A bind-mounted key keeps the host owner
# (uid 1000) and can't satisfy that. So, while we're still root (before the
# official entrypoint drops to the postgres user), copy the read-only mounted
# certs into a postgres-owned dir with strict perms, then hand off unchanged.
# ---------------------------------------------------------------------------
set -e

SRC=/etc/postgresql/certs-src
DST=/etc/postgresql/certs

if [ -d "$SRC" ]; then
    mkdir -p "$DST"
    cp "$SRC/server.crt" "$SRC/server.key" "$SRC/ca.crt" "$DST/"
    chown postgres:postgres "$DST"/server.crt "$DST"/server.key "$DST"/ca.crt
    chmod 600 "$DST/server.key"
    chmod 644 "$DST/server.crt" "$DST/ca.crt"
    echo "[postgres-entrypoint] installed TLS certs to $DST (postgres-owned, key 0600)"
else
    echo "[postgres-entrypoint] WARNING: $SRC not found — starting WITHOUT TLS." >&2
    echo "[postgres-entrypoint] run ./scripts/generate-postgres-certs.sh first." >&2
fi

# Hand off to the stock entrypoint (runs initdb + initdb.d on first boot, then
# execs the postgres command we were given).
exec docker-entrypoint.sh "$@"
