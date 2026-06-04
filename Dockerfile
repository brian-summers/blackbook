# Multi-stage build for Blackbook Rust application
# Stage 1: Build stage
# Use rust:bookworm so the binary links against glibc 2.36 — matches the
# debian:bookworm-slim runtime. rust:latest is on trixie (glibc 2.38) and
# produces binaries the runtime image cannot execute.
FROM rust:bookworm AS builder

LABEL maintainer="Blackbook Security Framework"
LABEL description="Secure cryptographic console application with PostgreSQL integration"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory in builder
WORKDIR /build

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release \
    && chmod +x target/release/blackbook

# Stage 2: Runtime stage
FROM debian:bookworm-slim

LABEL maintainer="Blackbook Security Framework"
LABEL description="Blackbook runtime with PostgreSQL client libraries"
LABEL security="Unprivileged user, minimal attack surface, secure defaults"

# Add runtime dependencies only (PostgreSQL client libraries, SSL support)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    postgresql-client \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user for running Blackbook
# User has no shell access, minimal permissions
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 1000 blackbook

# Create necessary directories with proper permissions
RUN mkdir -p /opt/blackbook/bin \
    && mkdir -p /opt/blackbook/certs \
    && mkdir -p /opt/blackbook/config \
    && mkdir -p /opt/blackbook/data \
    && chown -R blackbook:blackbook /opt/blackbook \
    && chmod 700 /opt/blackbook \
    && chmod 700 /opt/blackbook/data

# Copy compiled binary from builder
COPY --from=builder --chown=blackbook:blackbook /build/target/release/blackbook /opt/blackbook/bin/blackbook

# Set working directory
WORKDIR /opt/blackbook

# Switch to unprivileged user
USER blackbook

# Expose ports
# 8443: HTTPS API endpoint for Blackbook
EXPOSE 8443

# Health check - test connectivity to database
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /opt/blackbook/bin/blackbook health || exit 1

# Environment variables (will be overridden in docker-compose or runtime)
ENV RUST_LOG=info
ENV RUST_BACKTRACE=1
ENV DATABASE_URL=""
ENV BLACKBOOK_HTTPS_PORT=8443

# Entry point - runs Blackbook with init command first, then starts service
ENTRYPOINT ["/opt/blackbook/bin/blackbook"]
CMD ["health"]
