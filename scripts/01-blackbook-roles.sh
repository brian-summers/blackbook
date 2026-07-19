#!/bin/bash
# ---------------------------------------------------------------------------
# Blackbook Postgres role bootstrap — runs ONCE on a fresh data volume, inside
# the official image's docker-entrypoint-initdb.d, as the superuser, over the
# local socket. Replaces the old 01-init-postgres.sql, which referenced a
# phantom schema, used psql `-v` variables the entrypoint never supplied, and
# granted only USAGE (so the app couldn't create its real `blackbook_*` tables).
#
# It creates a least-privilege application role that can manage ONLY its own
# objects in this one database — it cannot create databases or roles, replicate,
# or bypass row-level security. The app connects as THIS role at runtime; the
# superuser is reserved for break-glass / migrations.
# ---------------------------------------------------------------------------
set -euo pipefail

APP_USER="${DB_USER:-blackbook_app}"
: "${DB_PASSWORD:?DB_PASSWORD must be set so the application role has a password}"

echo "[blackbook-init] creating least-privilege role '${APP_USER}' in '${POSTGRES_DB}'"

psql -v ON_ERROR_STOP=1 \
     -v app_user="$APP_USER" -v app_pass="$DB_PASSWORD" -v dbname="$POSTGRES_DB" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
	-- Application role: login + a password, but none of the cluster-level
	-- powers. NOBYPASSRLS keeps it subject to any future row-level policies.
	CREATE ROLE :"app_user" LOGIN PASSWORD :'app_pass'
	    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

	-- It may connect and manage objects only within this database's public
	-- schema (the app creates and owns its own `blackbook_*` tables there).
	GRANT CONNECT ON DATABASE :"dbname" TO :"app_user";
	GRANT USAGE, CREATE ON SCHEMA public TO :"app_user";

	-- Lock the door behind us: only named roles may connect to this database.
	REVOKE CONNECT ON DATABASE :"dbname" FROM PUBLIC;
EOSQL

# Optional read-only backup role (for pg_dump without the superuser). Created
# only when BACKUP_PASSWORD is supplied. Default privileges are set FOR the app
# role so the tables it later creates are readable by the backup role.
if [ -n "${BACKUP_PASSWORD:-}" ]; then
	BACKUP_USER="${DB_BACKUP_USER:-blackbook_backup}"
	echo "[blackbook-init] creating read-only backup role '${BACKUP_USER}'"
	psql -v ON_ERROR_STOP=1 \
	     -v app_user="$APP_USER" -v backup_user="$BACKUP_USER" \
	     -v backup_pass="$BACKUP_PASSWORD" -v dbname="$POSTGRES_DB" \
	     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
		CREATE ROLE :"backup_user" LOGIN PASSWORD :'backup_pass'
		    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		GRANT CONNECT ON DATABASE :"dbname" TO :"backup_user";
		GRANT USAGE ON SCHEMA public TO :"backup_user";
		-- See the app's future tables read-only.
		ALTER DEFAULT PRIVILEGES FOR ROLE :"app_user" IN SCHEMA public
		    GRANT SELECT ON TABLES TO :"backup_user";
	EOSQL
fi

echo "[blackbook-init] role bootstrap complete"
