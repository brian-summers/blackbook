# Multi-stage build for Blackbook. The image is both the server and the bbk CLI.
#
# Base images are pinned by digest, so a build uses exactly the bytes that were
# tested; Dependabot (.github/dependabot.yml) proposes new digests weekly, and
# CI scans the result before anything is published.
#
# Stage 1: build. The Rust version matches rust-toolchain.toml (CI checks), and
# the builder and runtime are both Debian trixie, so the binary links against
# the glibc the runtime has.
FROM rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS builder

# A failure anywhere in a pipeline fails the step.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /build

# Build the dependencies on their own first: this layer depends only on
# Cargo.toml and Cargo.lock, so a change to src/ doesn't recompile the ~400
# crates under it. The placeholder uses none of them, so cargo's
# unused_dependencies lint warns about each one here; that's expected.
#
# The placeholder main.rs and everything built from it are removed before the
# real sources arrive. Removing its fingerprint is what makes cargo rebuild
# the crate, since COPY keeps the sources' (older) mtimes. `cargo clean -p`
# finds the files wherever this cargo keeps them: deleting paths by hand broke
# when Rust 1.100 moved them from target/release/{deps,.fingerprint} to
# target/release/build/blackbook/.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && cargo clean --release --locked -p blackbook \
    && rm -rf src

# Only the sources: nothing else in the build context (credential bundles,
# secrets/, .env) can reach a layer, whatever .dockerignore says. The version
# check fails the build if the placeholder binary survived (it prints nothing).
COPY src ./src
RUN cargo build --release --locked \
    && { ./target/release/bbk --version | grep -q '^bbk ' \
         || { echo "error: target/release/bbk is the placeholder: cargo didn't rebuild it from src/" >&2; exit 1; }; }

# Stage 2: runtime.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

LABEL org.opencontainers.image.title="Blackbook" \
      org.opencontainers.image.description="End-to-end-encrypted secrets engine: server and bbk CLI" \
      org.opencontainers.image.source="https://github.com/brian-summers/blackbook" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Runtime packages: CA certificates only. OpenSSL and aws-lc are linked in
# statically and the app talks to Postgres through sqlx, so libssl and the
# Postgres client tools would only add attack surface (and CVEs to patch).
#
# Debian publishes fixes between base images, so the upgrade matters. Without
# APT_DAY, a build would reuse this layer from its cache until the base image
# digest changed, and miss those fixes. CI, release.yml and
# `scripts/check.sh docker` pass today's date (UTC), so the layer is rebuilt
# once a day. Within one build it stays cached, so a release pushes the image
# it tested.
ARG APT_DAY=
# hadolint ignore=DL3008
RUN echo "packages as of ${APT_DAY:-the cached day}" \
    && apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user for running Blackbook: no shell, no home beyond ~/.bbk.
# uid and gid 1000, the `user: "1000:1000"` docker-compose.yml runs it as.
RUN groupadd --system --gid 1000 blackbook \
    && useradd --system --no-create-home --shell /usr/sbin/nologin --uid 1000 --gid 1000 blackbook

# Create necessary directories with proper permissions
RUN mkdir -p /opt/blackbook/bin \
    && mkdir -p /opt/blackbook/certs \
    && mkdir -p /opt/blackbook/config \
    && mkdir -p /opt/blackbook/data \
    && chown -R blackbook:blackbook /opt/blackbook \
    && chmod 700 /opt/blackbook \
    && chmod 700 /opt/blackbook/data

# The image doubles as the CLI (scripts/bbk runs it), which keeps its encrypted
# profiles in ~/.bbk. Give the user a home holding only that directory: an
# empty named volume mounted over it (`-v bbk-home:/home/blackbook/.bbk`)
# inherits its owner and 0700 mode, so the unprivileged user can write to it.
RUN mkdir -p /home/blackbook/.bbk \
    && chown -R blackbook:blackbook /home/blackbook \
    && chmod 700 /home/blackbook/.bbk

# Copy compiled binary from builder (installed as /opt/blackbook/bin/bbk)
COPY --from=builder --chown=blackbook:blackbook /build/target/release/bbk /opt/blackbook/bin/bbk

WORKDIR /opt/blackbook

# Numeric, so a runtime can verify it isn't root (Kubernetes' runAsNonRoot can't
# resolve a user name).
USER 1000:1000

# 8443: HTTPS API endpoint for Blackbook
EXPOSE 8443

# Health check: database connectivity ping.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/opt/blackbook/bin/bbk", "health"]

# Environment variables (will be overridden in docker-compose or runtime)
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV DATABASE_URL=""
ENV BLACKBOOK_HTTPS_PORT=8443

ENTRYPOINT ["/opt/blackbook/bin/bbk"]
CMD ["health"]
