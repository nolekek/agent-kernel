# RFC 001: AgentKernel Core Architecture

> Status: **Approved**  
> Date: 2026-10-31  
> Scope: Core Runtime, Isolation Engine, Time-Travel CoW, Network Guard & MCP Server

---

## 1. Executive Summary

AgentKernel is an ultra-fast (<150ms boot), ephemeral micro-sandbox runtime with native Model Context Protocol (MCP) support designed specifically for autonomous AI coding agents.

This document formalizes the fundamental architectural decisions agreed upon during initial design.

---

## 2. Architectural Decisions (ADR)

### ADR-1: Primary Language & Platform Strategy
- **Decision**: **Rust + Linux-first** (with transparent WSL2/VM runner on Windows hosts).
- **Rationale**:
  - Direct, fine-grained access to Linux syscalls (`clone3`, `unshare`, `pivot_root`, `setns`, `seccomp-bpf`, `landlock`) without GC pauses.
  - Zero-runtime overhead guarantees <150ms cold boot and <15MB idle footprint per isolate.
  - Transparent WSL2/VM integration provides full kernel parity during local Windows development.

### ADR-2: Process Isolation Primitive
- **Decision**: **Custom Native Micro-Runtime in Rust** (`clone3`/`unshare`, cgroups v2, seccomp-bpf, Landlock).
- **Rationale**:
  - No external binary dependencies (e.g. `bwrap`, `dockerd`, `runc`).
  - Native control over PTY descriptors and process life cycle directly within the Tokio async runtime.
  - Sub-50ms process creation latency.

### ADR-3: Time-Travel CoW File System
- **Decision**: **Layered OverlayFS with dynamic upperdir branching**.
- **Rationale**:
  - Native Linux kernel support on any modern filesystem without custom partitioning.
  - User workspace is mounted as a read-only lowerdir; ephemeral writes go to an isolated upperdir.
  - Instant snapshots (<10ms) and rollback (<15ms) simply by remounting/swapping the active upperdir.

### ADR-4: Network Security & Egress Guard
- **Decision**: **Smart DNS Proxy + dynamic nftables allowlist (ipset)**.
- **Rationale**:
  - Default-deny outbound policy on isolated `netns`.
  - Built-in DNS resolver resolves queries and inspects domains against an approved allowlist (npm, PyPI, GitHub, etc.).
  - Whitelisted IPs are dynamically injected into nftables sets, preventing access to corporate intranets (`10.0.0.0/8`, `192.168.0.0/16`) and cloud instance metadata (`169.254.169.254`).

### ADR-5: MCP Transport & Protocol
- **Decision**: **Hybrid MCP Server (`stdio` default + optional HTTP/SSE)**.
- **Rationale**:
  - Zero-config connection to desktop AI coding tools (Claude Desktop, Cursor, Zed, Windsurf).
  - Streamable HTTP/SSE mode for cloud, web agents, and multi-tenant daemon orchestration.

---

## 3. Workspace Crates Layout

```
agent-kernel/
├── Cargo.toml                    # Virtual Workspace Manifest
├── crates/
│   ├── agentkernel-runtime/      # Low-level: Namespaces, cgroups v2, seccomp-bpf, Landlock
│   ├── agentkernel-fs/           # Storage: Layered OverlayFS, CoW snapshot tree, rollback
│   ├── agentkernel-net/          # Network: veth pair, Smart DNS interceptor, nftables allowlist
│   ├── agentkernel-pty/          # Terminal: PTY multiplexer, ANSI stream, Token Guard ring-buffer
│   ├── agentkernel-core/         # Core: Sandbox state machine, Warm Pool Manager, quotas, reaper
│   ├── agentkernel-mcp/          # Protocol: Model Context Protocol (JSON-RPC 2.0 over stdio & SSE)
│   └── agentkernel-cli/          # App Binary: CLI commands `mcp`, `daemon`, `exec`, `snapshot`
└── tests/                        # E2E integration tests
```
