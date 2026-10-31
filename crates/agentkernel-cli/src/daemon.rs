//! AgentKernel Production Daemon: Multi-Tenant HTTP/SSE & Prometheus Metrics Server.

use crate::tenant::{TenantConfig, TenantsRegistry};
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use agentkernel_mcp::server::AgentKernelMcpServer;
use anyhow::Context;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Configuration options for launching the AgentKernel daemon.
#[derive(Debug, Clone)]
pub struct DaemonOptions {
    /// Socket address to listen on (e.g. 127.0.0.1:8080 or 0.0.0.0:8080)
    pub addr: String,
    /// Optional global Bearer authentication token
    pub auth_token: Option<String>,
    /// Optional path to JSON registry with tenants and quotas
    pub tenants_file: Option<PathBuf>,
    /// HTTP path where Prometheus metrics are exposed (default: /metrics)
    pub metrics_path: String,
    /// Number of pre-warmed sandbox isolates
    pub warm_pool_size: usize,
}

/// Internal state for daemon statistics, metrics, and tenant session tracking.
pub struct DaemonState {
    pub start_time: Instant,
    pub requests_total: AtomicU64,
    pub requests_failed_total: AtomicU64,
    pub warm_pool_size: usize,
    pub auth_token: Option<String>,
    pub tenants_file: Option<PathBuf>,
    pub metrics_path: String,
    pub tenants_registry: RwLock<TenantsRegistry>,
    /// Maps session_id -> tenant_id (or "global")
    pub active_sessions: RwLock<HashMap<String, String>>,
    /// Maps tenant_id -> total requests
    pub tenant_requests: RwLock<HashMap<String, u64>>,
}

impl DaemonState {
    pub fn new(options: &DaemonOptions) -> Self {
        let registry = if let Some(ref path) = options.tenants_file {
            TenantsRegistry::load(path).unwrap_or_else(|e| {
                warn!("Could not load tenants file '{}': {e}. Using empty registry.", path.display());
                TenantsRegistry::default()
            })
        } else {
            TenantsRegistry::default()
        };

        Self {
            start_time: Instant::now(),
            requests_total: AtomicU64::new(0),
            requests_failed_total: AtomicU64::new(0),
            warm_pool_size: options.warm_pool_size,
            auth_token: options.auth_token.clone(),
            tenants_file: options.tenants_file.clone(),
            metrics_path: options.metrics_path.clone(),
            tenants_registry: RwLock::new(registry),
            active_sessions: RwLock::new(HashMap::new()),
            tenant_requests: RwLock::new(HashMap::new()),
        }
    }

    /// Refresh tenants registry from disk if configured.
    pub async fn reload_tenants(&self) {
        if let Some(ref path) = self.tenants_file {
            if let Ok(reg) = TenantsRegistry::load(path) {
                let mut guard = self.tenants_registry.write().await;
                *guard = reg;
            }
        }
    }

    /// Format Prometheus exposition metrics text.
    pub async fn generate_prometheus_metrics(&self) -> String {
        let uptime_secs = self.start_time.elapsed().as_secs();
        let total_reqs = self.requests_total.load(Ordering::Relaxed);
        let failed_reqs = self.requests_failed_total.load(Ordering::Relaxed);
        let rss_bytes = agentkernel_mcp::metrics::get_process_rss_bytes();

        let active_sessions_guard = self.active_sessions.read().await;
        let total_active_sandboxes = active_sessions_guard.len();

        let mut lines = Vec::new();

        lines.push("# HELP agentkernel_uptime_seconds Total daemon uptime in seconds".to_string());
        lines.push("# TYPE agentkernel_uptime_seconds counter".to_string());
        lines.push(format!("agentkernel_uptime_seconds {uptime_secs}"));

        lines.push("# HELP agentkernel_requests_total Total HTTP requests handled".to_string());
        lines.push("# TYPE agentkernel_requests_total counter".to_string());
        lines.push(format!("agentkernel_requests_total {total_reqs}"));

        lines.push("# HELP agentkernel_requests_failed_total Total failed or unauthorized requests".to_string());
        lines.push("# TYPE agentkernel_requests_failed_total counter".to_string());
        lines.push(format!("agentkernel_requests_failed_total {failed_reqs}"));

        lines.push("# HELP agentkernel_active_sandboxes Current active leased sandboxes".to_string());
        lines.push("# TYPE agentkernel_active_sandboxes gauge".to_string());
        lines.push(format!("agentkernel_active_sandboxes {total_active_sandboxes}"));

        lines.push("# HELP agentkernel_warm_pool_size Number of pre-warmed sandbox isolates".to_string());
        lines.push("# TYPE agentkernel_warm_pool_size gauge".to_string());
        lines.push(format!("agentkernel_warm_pool_size {}", self.warm_pool_size));

        lines.push("# HELP agentkernel_memory_rss_bytes Current process resident set size in bytes".to_string());
        lines.push("# TYPE agentkernel_memory_rss_bytes gauge".to_string());
        lines.push(format!("agentkernel_memory_rss_bytes {rss_bytes}"));

        // Tenant metrics
        let tenants_guard = self.tenants_registry.read().await;
        let tenant_reqs_guard = self.tenant_requests.read().await;

        if !tenants_guard.tenants.is_empty() {
            lines.push("# HELP agentkernel_tenant_quota Maximum sandbox quota for tenant".to_string());
            lines.push("# TYPE agentkernel_tenant_quota gauge".to_string());
            for t in &tenants_guard.tenants {
                lines.push(format!(
                    "agentkernel_tenant_quota{{tenant_id=\"{}\",tenant_name=\"{}\"}} {}",
                    t.id, t.name, t.max_sandboxes
                ));
            }

            lines.push("# HELP agentkernel_tenant_sandboxes_active Current active sandboxes leased by tenant".to_string());
            lines.push("# TYPE agentkernel_tenant_sandboxes_active gauge".to_string());
            for t in &tenants_guard.tenants {
                let count = active_sessions_guard.values().filter(|v| *v == &t.id).count();
                lines.push(format!(
                    "agentkernel_tenant_sandboxes_active{{tenant_id=\"{}\",tenant_name=\"{}\"}} {}",
                    t.id, t.name, count
                ));
            }

            lines.push("# HELP agentkernel_tenant_requests_total Total requests processed for tenant".to_string());
            lines.push("# TYPE agentkernel_tenant_requests_total counter".to_string());
            for t in &tenants_guard.tenants {
                let req_count = tenant_reqs_guard.get(&t.id).copied().unwrap_or(0);
                lines.push(format!(
                    "agentkernel_tenant_requests_total{{tenant_id=\"{}\",tenant_name=\"{}\"}} {}",
                    t.id, t.name, req_count
                ));
            }
        }

        lines.push(String::new());
        lines.join("\n")
    }
}

/// Runs the AgentKernel daemon until terminated.
pub async fn run_daemon(options: DaemonOptions) -> anyhow::Result<()> {
    let addr = options.addr.clone();
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind TCP listener to {addr}"))?;

    info!("============================================================");
    info!("        AgentKernel Micro-Sandbox Daemon Started            ");
    info!("============================================================");
    info!("  Listening Address: http://{addr}");
    info!("  Metrics Endpoint:  http://{addr}{}", options.metrics_path);
    info!("  Warm Pool Size:    {}", options.warm_pool_size);
    if let Some(ref path) = options.tenants_file {
        info!("  Tenants File:      {}", path.display());
    } else if options.auth_token.is_some() {
        info!("  Authentication:    Global Bearer Token active");
    } else {
        info!("  Authentication:    Open / Development mode");
    }
    info!("============================================================");

    let state = Arc::new(DaemonState::new(&options));
    let pool = Arc::new(LocalPoolManager::new(options.warm_pool_size));
    let mcp_server = Arc::new(AgentKernelMcpServer::new(pool));

    loop {
        let (mut socket, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("TCP accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        debug!("Connection accepted from {}", peer_addr);
        let state_cloned = state.clone();
        let mcp_cloned = mcp_server.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(state_cloned, mcp_cloned, &mut socket).await {
                debug!("HTTP connection closed: {e}");
            }
        });
    }
}

/// Handles an incoming HTTP connection: parsing request, authenticating, routing, and responding.
async fn handle_connection(
    state: Arc<DaemonState>,
    mcp_server: Arc<AgentKernelMcpServer>,
    socket: &mut TcpStream,
) -> anyhow::Result<()> {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = tokio::io::BufReader::new(reader);

    let mut request_line = String::new();
    if buf_reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    state.requests_total.fetch_add(1, Ordering::Relaxed);

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        state.requests_failed_total.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];

    let mut content_length = 0usize;
    let mut auth_header: Option<String> = None;
    let mut api_key_header: Option<String> = None;

    loop {
        let mut header_line = String::new();
        if buf_reader.read_line(&mut header_line).await? == 0 {
            break;
        }
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                if let Ok(len) = val.parse::<usize>() {
                    content_length = len;
                }
            } else if key == "authorization" {
                auth_header = Some(val);
            } else if key == "x-api-key" {
                api_key_header = Some(val);
            }
        }
    }

    // CORS pre-flight
    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                    Access-Control-Allow-Headers: Content-Type, Authorization, X-Api-Key\r\n\r\n";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Healthcheck endpoint (Always unauthenticated for Docker/Kubernetes probes)
    if method == "GET" && (uri == "/health" || uri == "/healthz") {
        let resp = "HTTP/1.1 200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Content-Length: 15\r\n\r\n\
                    {\"status\":\"ok\"}";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Prometheus Metrics endpoint
    let raw_path = uri.split('?').next().unwrap_or(uri);
    if method == "GET" && raw_path == state.metrics_path {
        let body = state.generate_prometheus_metrics().await;
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Authentication verification for data endpoints
    let authenticated_tenant: Option<TenantConfig> = match verify_auth(&state, auth_header.as_deref(), api_key_header.as_deref()).await {
        Ok(tenant) => tenant,
        Err(err_msg) => {
            state.requests_failed_total.fetch_add(1, Ordering::Relaxed);
            let body = json!({ "error": err_msg }).to_string();
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\n\
                 Content-Type: application/json\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            writer.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };

    // Record per-tenant request metric if applicable
    if let Some(ref t) = authenticated_tenant {
        let mut req_map = state.tenant_requests.write().await;
        *req_map.entry(t.id.clone()).or_insert(0) += 1;
    }

    // SSE Event Stream endpoint
    if method == "GET" && uri.starts_with("/sse") {
        let header = "HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Cache-Control: no-cache\r\n\
                      Connection: keep-alive\r\n\
                      Access-Control-Allow-Origin: *\r\n\r\n\
                      event: endpoint\r\ndata: /message\r\n\r\n";
        writer.write_all(header.as_bytes()).await?;
        writer.flush().await?;

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if writer.write_all(b": ping\n\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    // JSON-RPC HTTP POST handling (/message, /mcp, /)
    if method == "POST" {
        let mut body = vec![0u8; content_length];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;

        let rpc_req: Result<JsonRpcRequest, _> = serde_json::from_slice(&body);
        let resp_body = match rpc_req {
            Ok(req) => {
                // Multi-tenant quota enforcement on sandbox acquisition
                if req.method == "tools/call" {
                    if let Some(params) = req.params.as_ref() {
                        if params.get("name").and_then(|n| n.as_str()) == Some("sandbox_acquire") {
                            if let Some(ref tenant) = authenticated_tenant {
                                let active_guard = state.active_sessions.read().await;
                                let tenant_active = active_guard.values().filter(|v| *v == &tenant.id).count();
                                if tenant_active >= tenant.max_sandboxes {
                                    state.requests_failed_total.fetch_add(1, Ordering::Relaxed);
                                    let err_res = JsonRpcResponse::error(
                                        req.id,
                                        JsonRpcError {
                                            code: -32000,
                                            message: format!(
                                                "Quota exceeded: Tenant '{}' has reached max sandbox limit of {}",
                                                tenant.id, tenant.max_sandboxes
                                            ),
                                            data: None,
                                        },
                                    );
                                    let json_bytes = serde_json::to_vec(&err_res)?;
                                    let resp_header = format!(
                                        "HTTP/1.1 200 OK\r\n\
                                         Content-Type: application/json\r\n\
                                         Access-Control-Allow-Origin: *\r\n\
                                         Content-Length: {}\r\n\r\n",
                                        json_bytes.len()
                                    );
                                    writer.write_all(resp_header.as_bytes()).await?;
                                    writer.write_all(&json_bytes).await?;
                                    writer.flush().await?;
                                    return Ok(());
                                }
                            }
                        }
                    }
                }

                let res = mcp_server.handle_request(req).await;

                // Track sandbox session creation and release in active_sessions
                if let Some(ref result_val) = res.result {
                    if let Some(content) = result_val.get("content").and_then(|c| c.as_array()) {
                        for item in content {
                            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                                    let tenant_id = authenticated_tenant.as_ref().map(|t| t.id.clone()).unwrap_or_else(|| "global".to_string());
                                    if let Some(session_id) = parsed.get("session_id").and_then(|s| s.as_str()) {
                                        if parsed.get("status").and_then(|s| s.as_str()) == Some("leased") {
                                            let mut active_guard = state.active_sessions.write().await;
                                            active_guard.insert(session_id.to_string(), tenant_id);
                                        } else if parsed.get("status").and_then(|s| s.as_str()) == Some("released") {
                                            let mut active_guard = state.active_sessions.write().await;
                                            active_guard.remove(session_id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                serde_json::to_vec(&res)?
            }
            Err(e) => {
                state.requests_failed_total.fetch_add(1, Ordering::Relaxed);
                let err_res = JsonRpcResponse::error(
                    None,
                    JsonRpcError::parse_error(format!("Invalid JSON-RPC payload: {e}")),
                );
                serde_json::to_vec(&err_res)?
            }
        };

        let response_headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\r\n",
            resp_body.len()
        );

        writer.write_all(response_headers.as_bytes()).await?;
        writer.write_all(&resp_body).await?;
        writer.flush().await?;
        return Ok(());
    }

    // Default 404
    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    writer.write_all(not_found.as_bytes()).await?;
    Ok(())
}

/// Helper to authenticate a request against global auth token or tenants file.
async fn verify_auth(
    state: &DaemonState,
    auth_header: Option<&str>,
    api_key_header: Option<&str>,
) -> Result<Option<TenantConfig>, String> {
    // If tenants file is active, check against tenant registry
    if state.tenants_file.is_some() {
        let key = extract_token(auth_header).or(api_key_header);
        match key {
            Some(token) => {
                // Ensure latest tenant data is read
                state.reload_tenants().await;
                let registry = state.tenants_registry.read().await;
                if let Some(tenant) = registry.find_by_api_key(token) {
                    return Ok(Some(tenant.clone()));
                } else {
                    return Err("Invalid tenant API key".to_string());
                }
            }
            None => return Err("Missing tenant authentication (Bearer token or X-Api-Key required)".to_string()),
        }
    }

    // If global auth token is active
    if let Some(ref required_token) = state.auth_token {
        let provided = extract_token(auth_header);
        match provided {
            Some(token) if token == required_token => Ok(None),
            _ => Err("Invalid or missing global Bearer token".to_string()),
        }
    } else {
        // No authentication required
        Ok(None)
    }
}

fn extract_token(auth_header: Option<&str>) -> Option<&str> {
    if let Some(hdr) = auth_header {
        let trimmed = hdr.trim();
        if let Some(token) = trimmed.strip_prefix("Bearer ") {
            return Some(token.trim());
        } else if let Some(token) = trimmed.strip_prefix("bearer ") {
            return Some(token.trim());
        }
        return Some(trimmed);
    }
    None
}
