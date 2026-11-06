#!/usr/bin/env bash
# End-to-end test of a Blackbook image, deployed the way docker-compose.yml
# deploys it (Postgres over mutual TLS, a read-only app container, a keyfile
# master key) and driven by the image's own bbk CLI.
#
#   scripts/e2e.sh [IMAGE]        default: blackbook:check (`scripts/check.sh docker` builds it)
#
# Hermetic and safe next to a real stack: it copies the compose file, configs
# and scripts into a temporary directory, generates throwaway secrets there,
# and runs under its own compose project, container names, port and subnet.
# It never reads or writes ./secrets, ./.env or ~/.bbk, and it removes
# everything it created when it exits. Override BBK_E2E_PORT or BBK_E2E_SUBNET
# if either is taken on your machine.
#
# Every bbk call below goes through the CLI's TLS client, which offers only the
# post-quantum X25519MLKEM768 key exchange, so each one that succeeds also shows
# that the server negotiated it.
set -euo pipefail

IMAGE=${1:-blackbook:check}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROJECT=${BBK_E2E_PROJECT:-bbke2e$$}
PORT=${BBK_E2E_PORT:-18443}
SUBNET=${BBK_E2E_SUBNET:-172.31.250.0/24}
BUSYBOX=busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
CURL=curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
NET=${PROJECT}_blackbook_network
PASSPHRASE="e2e profile passphrase $$"
SECRET="e2e-value-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
WORK=$(mktemp -d)
failures=0

# Git Bash: keep container paths away from MSYS path conversion.
dock() { MSYS_NO_PATHCONV=1 docker "$@"; }
compose() { (cd "$WORK" && dock compose -p "$PROJECT" -f docker-compose.yml -f e2e.override.yml "$@"); }

ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/        /'; failures=$((failures + 1)); }
# expect NAME CMD...: CMD succeeds.
expect() { local name=$1 out; shift; if out=$("$@" 2>&1); then ok "$name"; else bad "$name" "$out"; fi; }
# refuse NAME WHY CMD...: CMD fails, and its output matches the regex WHY, so
# it failed for the reason under test (a 404 is not an access-control denial).
refuse() {
    local name=$1 why=$2 out; shift 2
    if out=$("$@" 2>&1); then bad "$name (it succeeded)" "$out"
    elif [[ $out =~ $why ]]; then ok "$name"
    else bad "$name (failed, but not with /$why/)" "$out"; fi
}
# same NAME WANT CMD...: CMD prints exactly WANT.
same() { local name=$1 want=$2 out; shift 2; if out=$("$@" 2>&1) && [ "$out" = "$want" ]; then ok "$name"; else bad "$name" "$out"; fi; }
# status NAME WANT PATH [CURL-ARGS...]: the HTTP status is one of WANT (a
# regex). curl runs in a container on the stack's network and offers only
# classical key exchange, standing in for any non-bbk TLS client.
status() {
    local name=$1 want=$2 path=$3 code; shift 3
    code=$(dock run --rm --network "$NET" -v "$PROJECT-ca:/ca:ro" "$CURL" -s -o /dev/null \
        -w '%{http_code}' --curves X25519:P-256 --cacert /ca/ca.crt "$@" "https://blackbook:8443$path" || true)
    if [[ $code =~ ^($want)$ ]]; then ok "$name ($code)"; else bad "$name (got HTTP $code)"; fi
}

# The image's CLI on the stack's network. Each identity has its own home
# volume, as if it were on its own machine.
cli_args() {
    printf '%s\n' --network "$NET" -e HOME=/home/blackbook -e BLACKBOOK_NO_PROMPT=1 \
        -e BLACKBOOK_PASSPHRASE="$PASSPHRASE" -e BLACKBOOK_PROFILE="$1" \
        -v "$PROJECT-home-$1:/home/blackbook/.bbk"
}
bbk() { local who=$1; shift; local a; mapfile -t a < <(cli_args "$who"); dock run --rm -i "${a[@]}" "$IMAGE" "$@"; }
bbk_sh() { local a; mapfile -t a < <(cli_args "$1"); dock run --rm "${a[@]}" --entrypoint sh "$IMAGE" -c "$2"; }
login() { printf '%s' "$2" | bbk "$1" login --server https://blackbook:8443 -; }

cleanup() {
    local rc=$?
    if [ "$failures" -gt 0 ] || [ "$rc" -ne 0 ]; then
        echo; echo "== logs"; compose logs --no-color --tail 60 2>&1 || true
        for c in bob alice web; do dock logs --tail 20 "$PROJECT-$c" 2>&1 | sed "s/^/$c: /" || true; done
    fi
    dock rm -f "$PROJECT-bob" "$PROJECT-alice" "$PROJECT-web" >/dev/null 2>&1 || true
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    dock volume ls -q --filter "name=$PROJECT-" | while read -r v; do dock volume rm "$v" >/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "== stack: $IMAGE as compose project $PROJECT (port $PORT, subnet $SUBNET)"
mkdir -p "$WORK/config" "$WORK/scripts" "$WORK/secrets"
cp "$ROOT/docker-compose.yml" "$WORK/"
cp "$ROOT/config/postgres.conf" "$ROOT/config/pg_hba.conf" "$WORK/config/"
cp "$ROOT/scripts/01-blackbook-roles.sh" "$ROOT/scripts/postgres-entrypoint.sh" \
   "$ROOT/scripts/generate-postgres-certs.sh" "$WORK/scripts/"
# The shipped pg_hba.conf admits only the compose subnet; move it to the test subnet.
sed "s#172\.25\.0\.0/16#$SUBNET#" "$ROOT/config/pg_hba.conf" > "$WORK/config/pg_hba.conf"
grep -qF "$SUBNET" "$WORK/config/pg_hba.conf" ||
    { echo "pg_hba.conf no longer admits 172.25.0.0/16; update scripts/e2e.sh" >&2; exit 1; }
bash "$WORK/scripts/generate-postgres-certs.sh" >/dev/null
openssl rand 32 > "$WORK/secrets/master_keyfile"
# The app runs as uid 1000 and reads the keyfile and its Postgres client key
# through bind mounts. Where the host user isn't uid 1000 (CI runners are
# 1001), make these throwaway copies readable to it.
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" != 1000 ]; then
    chmod 644 "$WORK/secrets/master_keyfile" "$WORK/secrets/postgres/client.key"
fi
printf 'DB_ADMIN_PASSWORD=%s\nDB_PASSWORD=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" > "$WORK/.env"
cat > "$WORK/e2e.override.yml" <<EOF
# Test-only differences from docker-compose.yml: the image under test, and
# names, a port and a subnet that can't collide with a real stack.
services:
  postgres:
    container_name: $PROJECT-postgres
  blackbook:
    image: $IMAGE
    container_name: $PROJECT-app
    ports: !override
      - "127.0.0.1:$PORT:8443"
networks:
  blackbook_network:
    ipam:
      config: !override
        - subnet: $SUBNET
EOF
compose up -d --wait --wait-timeout 180 --no-build >/dev/null
ADMIN_BUNDLE=""
for _ in $(seq 30); do
    ADMIN_BUNDLE=$(compose exec -T blackbook cat /opt/blackbook/data/admin-bundle.json 2>/dev/null) && break
    sleep 1
done
[ -n "$ADMIN_BUNDLE" ] || { echo "the server never wrote admin-bundle.json" >&2; exit 1; }
compose exec -T blackbook cat /opt/blackbook/data/ca.crt |
    dock run --rm -i -v "$PROJECT-ca:/ca" "$BUSYBOX" sh -c 'cat > /ca/ca.crt'
TOKEN=$(printf '%s' "$ADMIN_BUNDLE" | grep -oE 'bbk_[A-Za-z0-9_-]{43}' | head -n 1)
echo "  up: postgres and blackbook healthy"

echo "== server, seen from a classical TLS client (curl)"
status "health check answers over the pinned CA" 200 /health
status "API refuses a request with no credentials" '401|403' /api/v1/whoami
status "API refuses a valid token without its client certificate" '401|403' /api/v1/whoami \
    -H "Authorization: Bearer $TOKEN"

echo "== admin"
expect "admin logs in with the first-run bundle" login admin "$ADMIN_BUNDLE"
expect "whoami" bbk admin whoami
expect "store a secret" bbk admin put e2e-db-password "$SECRET"
same "read it back" "$SECRET" bbk admin get e2e-db-password
refuse "a second put of the same name is refused" '409|exists' bbk admin put e2e-db-password other
expect "file round trip, 1 MiB" bbk_sh admin '
    head -c 1048576 /dev/urandom > /tmp/blob &&
    /opt/blackbook/bin/bbk file put /tmp/blob >/dev/null &&
    /opt/blackbook/bin/bbk file get blob /tmp/back >/dev/null &&
    [ "$(sha256sum < /tmp/blob)" = "$(sha256sum < /tmp/back)" ]'

echo "== access control, in a shared domain"
ALICE=$(bbk admin client create alice 2>/dev/null) || true
BOB=$(bbk admin client create bob 2>/dev/null) || true
expect "admin creates clients alice and bob" test -n "$ALICE" -a -n "$BOB"
expect "alice logs in" login alice "$ALICE"
expect "admin creates domain e2e" bbk admin domain create e2e
expect "admin stores a secret in it" bbk admin put -D e2e app-db-password "$SECRET"
refuse "alice, not a member of e2e, can't read it" '\[not_member\]' bbk alice get -D e2e app-db-password
refuse "alice can't create clients (admin only)" '\[forbidden\]' bbk alice client create mallory
refuse "alice can't read the audit log (admin only)" '\[forbidden\]' bbk alice audit
expect "admin adds alice to e2e" bbk admin domain add-member e2e alice
refuse "a member without a grant still can't read it" '\[forbidden\]' \
    bbk alice get -D e2e app-db-password
expect "admin grants alice read on app-* in e2e" bbk admin acl grant -D e2e alice 'app-*' --read
same "alice reads the secret under the grant" "$SECRET" bbk alice get -D e2e app-db-password
refuse "the read grant doesn't let alice overwrite it" '\[forbidden\]' \
    bbk alice put -D e2e app-db-password changed --overwrite
same "the value is unchanged" "$SECRET" bbk admin get -D e2e app-db-password

echo "== tunnel: alice -> relay -> bob -> a web server only bob can reach"
expect "bob logs in" login bob "$BOB"
dock run -d --name "$PROJECT-web" --network "$NET" --network-alias e2e-web "$BUSYBOX" sh -c \
    'mkdir /www && head -c 1048576 /dev/urandom > /www/blob && sha256sum /www/blob > /www/blob.sha256 && exec httpd -f -p 8080 -h /www' >/dev/null
mapfile -t A < <(cli_args bob)
dock run -d --name "$PROJECT-bob" "${A[@]}" "$IMAGE" tunnel accept --from alice --wait-timeout 60 >/dev/null
sleep 3
mapfile -t A < <(cli_args alice)
dock run -d --name "$PROJECT-alice" "${A[@]}" "$IMAGE" tunnel forward bob --listen 127.0.0.1:18500 --to e2e-web:8080 >/dev/null
want=""; got=""
for _ in $(seq 20); do
    want=$(dock run --rm --network "container:$PROJECT-alice" "$BUSYBOX" wget -qO- http://127.0.0.1:18500/blob.sha256 2>/dev/null | cut -d' ' -f1) && [ -n "$want" ] && break
    sleep 1
done
got=$(dock run --rm --network "container:$PROJECT-alice" "$BUSYBOX" sh -c 'wget -qO- http://127.0.0.1:18500/blob | sha256sum' 2>/dev/null | cut -d' ' -f1) || true
if [ -n "$want" ] && [ "$got" = "$want" ]; then ok "1 MiB through the tunnel, unchanged"; else bad "tunnel transfer (want ${want:-nothing}, got ${got:-nothing})"; fi

echo "== audit and persistence"
expect "audit log hash chain verifies" bbk admin audit --verify
compose restart blackbook >/dev/null 2>&1
compose up -d --wait --wait-timeout 120 --no-build >/dev/null 2>&1
same "the secret survives a server restart (master key unwrapped from the keyfile)" "$SECRET" bbk admin get e2e-db-password

echo
if [ "$failures" -eq 0 ]; then echo "e2e: all checks passed"; else echo "e2e: $failures check(s) failed"; exit 1; fi
