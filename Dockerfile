# Multi-stage build for Blackbook. The image is both the server and the bbk CLI.
#
# Base images are pinned by digest, so a build uses exactly the bytes that were
# tested; Dependabot (.github/dependabot.yml) proposes new digests weekly, and
# CI scans the result before anything is published.
#
# Stage 1: build. The Rust version matches rust-toolchain.toml (CI checks), and
# the builder and runtime are both Debian trixie, so the binary links against
# the glibc the runtime has.
FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS builder

# A failure anywhere in a pipeline fails the step.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

WORKDIR /build

# Build the dependencies on their own first: this layer depends only on
# Cargo.toml and Cargo.lock, so a change to src/ doesn't recompile the ~400
# crates under it. The placeholder main.rs and everything built from it are
# deleted before the real sources arrive. Deleting the fingerprint is what
# makes cargo rebuild the crate, since COPY keeps the sources' (older) mtimes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/bbk target/release/bbk.d \
              target/release/deps/bbk-* target/release/.fingerprint/blackbook-*

# Only the sources: nothing else in the build context (credential bundles,
# secrets/, .env) can reach a layer, whatever .dockerignore says. The version
# check fails the build if the placeholder binary survived (it prints nothing).
COPY src ./src
RUN cargo build --release --locked \
    && ./target/release/bbk --version | grep -q '^bbk '

# Stage 2: runtime.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

LABEL org.opencontainers.image.title="Blackbook" \
      org.opencontainers.image.description="End-to-end-encrypted secrets engine: server and bbk CLI" \
      org.opencontainers.image.source="https://github.com/brian-summers/blackbook" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Runtime packages: CA certificates only. OpenSSL and aws-lc are linked in
# statically and the app talks to Postgres through sqlx, so libssl and the
# Postgres client tools would only add attack surface (and CVEs to patch).
# hadolint ignore=DL3008
RUN apt-get update \
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
