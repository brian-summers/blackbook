#!/usr/bin/env bash
# The project's checks, in one place. The git hooks, CI and you all run this
# script, so a check that passes locally passes in CI.
#
#   scripts/check.sh              what the pre-push hook runs: pins fmt clippy test deny
#   scripts/check.sh all          all of the above, plus msrv, workflows,
#                                 dockerfile, gitleaks, docker, scan and e2e
#   scripts/check.sh STEP...      any steps, in the order given
#
# Steps:
#   staged      what the pre-commit hook runs: no secrets or credential
#               bundles in the staged changes, Rust code formatted
#   pins        toolchain, base images and GitHub Actions are pinned and agree
#   fmt         rustfmt
#   clippy      clippy, every warning an error
#   test        the test suite
#   deny        cargo-deny: advisories, licences, banned crates, sources
#   msrv        builds with the minimum Rust version in Cargo.toml
#   coverage    line coverage (cargo-llvm-cov), lcov written to target/lcov.info
#   workflows   actionlint and zizmor on .github/workflows
#   dockerfile  hadolint
#   gitleaks    secret scan of the whole git history
#   docker      builds the image as $BBK_IMAGE (default blackbook:check)
#   scan        Grype on $BBK_IMAGE: fails on a high or critical CVE that has a fix
#   e2e         scripts/e2e.sh against $BBK_IMAGE
#
# Locally a missing optional tool (cargo-deny, cargo-llvm-cov, gitleaks, Docker)
# skips its step with a note; in CI ($CI set) it fails the step instead.
set -euo pipefail
cd "$(dirname "$0")/.."

# Tool images, pinned by digest. Bump deliberately, after reading the release notes.
ACTIONLINT_IMAGE=rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
ZIZMOR_IMAGE=ghcr.io/zizmorcore/zizmor:1.32.0@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d
HADOLINT_IMAGE=hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d
GITLEAKS_IMAGE=ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
GRYPE_IMAGE=anchore/grype:v0.121.2@sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913

BBK_IMAGE=${BBK_IMAGE:-blackbook:check}

# What must never be committed. The PEM pattern is split so this file doesn't
# match itself.
PEM_RE='-----BEGIN ([A-Z0-9]+ )*PRIVATE'' KEY-----'
TOKEN_RE='bbk_[A-Za-z0-9_-]{43}'

# Git Bash on Windows puts MSYS perl first on PATH, and it can't configure the
# vendored OpenSSL build. Strawberry Perl (which the Windows build needs anyway)
# can.
if [ -z "${OPENSSL_SRC_PERL:-}" ] && [ -x /c/Strawberry/perl/bin/perl.exe ]; then
    export OPENSSL_SRC_PERL=C:/Strawberry/perl/bin/perl.exe
fi

note() { printf '\n== %s\n' "$*"; }
die() { printf 'check: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
# Git Bash: keep container paths such as /repo away from MSYS path conversion.
dock() { MSYS_NO_PATHCONV=1 docker "$@"; }
# The repository as a path the Docker daemon understands (C:/... on Windows).
host_pwd() { if have cygpath; then cygpath -m "$PWD"; else printf '%s' "$PWD"; fi; }
# A missing tool fails in CI and skips locally.
need() {
    have "$1" && return 0
    [ -n "${CI:-}" ] && die "$1 is required in CI but not installed"
    printf '   skipped: %s is not installed (%s)\n' "$1" "$2"
    return 1
}

step_staged() {
    note "staged: secrets and formatting"
    local bad=0 f
    # Paths that never belong in the repository. .gitignore covers them, but
    # `git add -f` gets past it.
    while IFS= read -r -d '' f; do
        case "$f" in
            .env.example) ;;
            secrets/* | */secrets/* | .env | .env.* | *.key | *.p12 | *.pfx | \
            *bundle*.json | admin*.json | user*.json | *master_keyfile* | *master_passphrase*)
                printf '   %s: looks like a secret or a credential bundle\n' "$f"; bad=1 ;;
        esac
    done < <(git diff --cached --name-only --diff-filter=ACMR -z)
    # Private keys and Blackbook tokens on any added line.
    local hits
    hits=$(git diff --cached -U0 --diff-filter=ACMR --no-color | awk -v re="$PEM_RE|$TOKEN_RE" '
        /^\+\+\+ / { file = substr($0, 7); next }
        /^\+/ && $0 ~ re { print "   " file ": a private key or a bbk_ token" }' | sort -u)
    if [ -n "$hits" ]; then printf '%s\n' "$hits"; bad=1; fi
    if have gitleaks; then
        gitleaks git --pre-commit --staged --redact --no-banner --config .gitleaks.toml || bad=1
    fi
    if [ "$bad" -ne 0 ]; then
        die "refusing to commit. Unstage it (git restore --staged FILE); if this is a false positive, add it to .gitleaks.toml or commit with --no-verify and say why in the PR."
    fi
    if git diff --cached --name-only --diff-filter=ACMR | grep -q '\.rs$'; then
        cargo fmt --all --check || die "run \`cargo fmt --all\`, then stage the result"
    fi
}

step_pins() {
    note "pins"
    local toolchain image unpinned
    toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
    image=$(sed -n 's/^FROM rust:\([0-9][0-9.]*\)-.*/\1/p' Dockerfile)
    [ -n "$toolchain" ] && [ "$toolchain" = "$image" ] ||
        die "rust-toolchain.toml says Rust $toolchain but the Dockerfile builds with rust:$image; make them agree"
    unpinned=$(grep -nE '^\s*FROM ' Dockerfile | grep -v '@sha256:[0-9a-f]\{64\}' || true)
    [ -z "$unpinned" ] || die "Dockerfile base images must be pinned by digest:"$'\n'"$unpinned"
    unpinned=$(grep -nE '^\s*(- )?uses:' .github/workflows/*.yml |
        grep -vE 'uses: *(\./|\$/)|@[0-9a-f]{40}( |$)' || true)
    [ -z "$unpinned" ] || die "actions must be pinned to a full commit SHA (with the version in a comment):"$'\n'"$unpinned"
    echo "   Rust $toolchain everywhere; base images and actions pinned"
}

step_fmt() { note "rustfmt"; cargo fmt --all --check; }

step_clippy() { note "clippy"; cargo clippy --all-targets --locked -- -D warnings; }

step_test() { note "tests"; cargo test --locked; }

step_deny() {
    note "cargo-deny"
    need cargo-deny "cargo install --locked cargo-deny" || return 0
    cargo deny --locked check --hide-inclusion-graph
}

step_msrv() {
    local msrv
    msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
    note "msrv: Rust $msrv"
    rustup toolchain install "$msrv" --profile minimal --no-self-update
    cargo "+$msrv" check --locked --all-targets
}

step_coverage() {
    note "coverage"
    need cargo-llvm-cov "cargo install --locked cargo-llvm-cov" || return 0
    local out="${CARGO_TARGET_DIR:-target}/lcov.info"
    cargo llvm-cov --locked --no-report
    cargo llvm-cov report --lcov --output-path "$out"
    cargo llvm-cov report --summary-only
    echo "   lcov report: $out"
}

step_workflows() {
    note "workflows: actionlint, zizmor"
    need docker "https://docs.docker.com/get-docker/" || return 0
    dock run --rm -v "$(host_pwd):/repo:ro" -w /repo "$ACTIONLINT_IMAGE" -color
    # zizmor's online audits (known-vulnerable or impostor action commits) need
    # a token; without one it runs the offline audits.
    local online=(--offline)
    [ -n "${GH_TOKEN:-}" ] && online=()
    dock run --rm -e GH_TOKEN -v "$(host_pwd):/repo:ro" -w /repo "$ZIZMOR_IMAGE" \
        "${online[@]}" --min-severity low .github/workflows
}

step_dockerfile() {
    note "hadolint"
    need docker "https://docs.docker.com/get-docker/" || return 0
    dock run --rm -i "$HADOLINT_IMAGE" hadolint --failure-threshold warning - < Dockerfile
}

step_gitleaks() {
    note "gitleaks: full history"
    need docker "https://docs.docker.com/get-docker/" || return 0
    # The mounted checkout belongs to another uid, which git refuses to read
    # unless it is marked safe.
    dock run --rm -v "$(host_pwd):/repo:ro" -w /repo \
        -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
        "$GITLEAKS_IMAGE" git --redact --no-banner --config .gitleaks.toml /repo
}

step_docker() {
    note "docker build: $BBK_IMAGE"
    need docker "https://docs.docker.com/get-docker/" || return 0
    dock build -t "$BBK_IMAGE" .
}

# Scans an exported copy of the image, so the scanner never gets the Docker
# socket (which would give it root on the host). BBK_SARIF=PATH also writes a
# SARIF report for GitHub code scanning.
step_scan() {
    note "grype: $BBK_IMAGE"
    need docker "https://docs.docker.com/get-docker/" || return 0
    local tmp mnt rc=0
    tmp=$(mktemp -d)
    if have cygpath; then mnt=$(cygpath -m "$tmp"); else mnt=$tmp; fi
    dock save "$BBK_IMAGE" -o "$mnt/image.tar"
    # The vulnerability database is cached in a volume between local runs.
    dock run --rm -v "$mnt:/scan" -v bbk-grype-db:/root/.cache/grype \
        "$GRYPE_IMAGE" docker-archive:/scan/image.tar --only-fixed --fail-on high \
        -o table ${BBK_SARIF:+-o sarif=/scan/grype.sarif} || rc=$?
    if [ -n "${BBK_SARIF:-}" ] && [ -f "$tmp/grype.sarif" ]; then cp "$tmp/grype.sarif" "$BBK_SARIF"; fi
    rm -rf "$tmp"
    [ "$rc" -eq 0 ] || die "the image has a high or critical vulnerability with a fix available: update the base image digest (or the package) and rebuild"
}

step_e2e() {
    need docker "https://docs.docker.com/get-docker/" || return 0
    scripts/e2e.sh "$BBK_IMAGE"
}

steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(pins fmt clippy test deny)
[ "${steps[*]}" != all ] || steps=(pins fmt clippy test deny msrv workflows dockerfile gitleaks docker scan e2e)
for s in "${steps[@]}"; do
    declare -F "step_$s" >/dev/null || die "unknown step '$s' (see the top of $0)"
done
for s in "${steps[@]}"; do "step_$s"; done
note "passed: ${steps[*]}"
