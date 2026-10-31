# syntax=docker/dockerfile:1.4
# ==============================================================================
# AgentKernel Production Multi-Stage Container Image
# Stage 1: Build & Dependency Caching (Rust 1.82 on Debian Bookworm)
# Stage 2: Minimal Production Runtime (Debian Bookworm Slim + Rootless Security)
# ==============================================================================

# --- Stage 1: Builder ---
FROM rust:1.82-bookworm AS builder

WORKDIR /usr/src/agentkernel

# 1. Copy workspace manifests and crate definitions for layer caching
COPY Cargo.toml Cargo.lock* ./
COPY crates/agentkernel-core/Cargo.toml crates/agentkernel-core/
COPY crates/agentkernel-runtime/Cargo.toml crates/agentkernel-runtime/
COPY crates/agentkernel-fs/Cargo.toml crates/agentkernel-fs/
COPY crates/agentkernel-net/Cargo.toml crates/agentkernel-net/
COPY crates/agentkernel-pty/Cargo.toml crates/agentkernel-pty/
COPY crates/agentkernel-mcp/Cargo.toml crates/agentkernel-mcp/
COPY crates/agentkernel-cli/Cargo.toml crates/agentkernel-cli/

# 2. Scaffold dummy crates to pre-compile and cache dependency layers
RUN mkdir -p \
    crates/agentkernel-core/src \
    crates/agentkernel-runtime/src \
    crates/agentkernel-fs/src \
    crates/agentkernel-net/src \
    crates/agentkernel-pty/src \
    crates/agentkernel-mcp/src \
    crates/agentkernel-cli/src \
    tests && \
    echo "pub fn dummy() {}" > crates/agentkernel-core/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/agentkernel-runtime/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/agentkernel-fs/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/agentkernel-net/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/agentkernel-pty/src/lib.rs && \
    echo "pub fn dummy() {}" > crates/agentkernel-mcp/src/lib.rs && \
    echo "fn main() {}" > crates/agentkernel-cli/src/main.rs && \
    echo "fn main() {}" > tests/integration_test.rs && \
    echo "fn main() {}" > tests/metrics_e2e_test.rs && \
    echo "fn main() {}" > tests/multi_tenant_e2e_test.rs

RUN cargo build --release --bin agentkernel

# 3. Purge dummy source files and compile actual application code
RUN rm -rf crates/*/src tests target/release/deps/agentkernel* target/release/agentkernel*

COPY crates crates
COPY tests tests

RUN cargo build --release --bin agentkernel

# --- Stage 2: Production Runtime ---
FROM debian:bookworm-slim AS runtime

LABEL maintainer="AgentKernel Contributors <https://github.com/nolekek/agent-kernel>"
LABEL description="High-Performance Ephemeral Micro-Sandbox Runtime & Multi-Tenant MCP Server"

# 1. Install production utilities and network isolation tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nftables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Create non-privileged user and application state directory
RUN groupadd -g 10001 agentkernel && \
    useradd -u 10001 -g agentkernel -s /bin/bash -m -d /home/agentkernel agentkernel && \
    mkdir -p /var/lib/agentkernel && \
    chown -R agentkernel:agentkernel /var/lib/agentkernel /home/agentkernel

# 3. Copy compiled release binary from builder
COPY --from=builder /usr/src/agentkernel/target/release/agentkernel /usr/local/bin/agentkernel

# 4. Enforce non-root execution and configure container environment
USER agentkernel
WORKDIR /var/lib/agentkernel

ENV RUST_LOG=info \
    AGENTKERNEL_DATA_DIR=/var/lib/agentkernel

EXPOSE 8080

# 5. Container healthcheck probing Prometheus metrics endpoint
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/metrics || exit 1

ENTRYPOINT ["agentkernel", "daemon", "--addr", "0.0.0.0:8080"]
