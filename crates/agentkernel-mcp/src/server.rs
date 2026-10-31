//! AgentKernel MCP Server (JSON-RPC 2.0 over stdio & HTTP/SSE).

use crate::diff::compute_directory_diff;
use crate::local_pool::LocalPoolManager;
use crate::metrics::{compute_dir_size, get_process_rss_bytes, SandboxMetrics};
use crate::protocol::*;
use crate::tools::*;
use agentkernel_core::metrics::MetricsRegistry;
use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::{SandboxConfig, SandboxSession};
use agentkernel_core::tenant::{TenantId, TenantManager};
use agentkernel_core::CoreError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("JSON-RPC parsing error: {0}")]
    JsonRpc(String),
    #[error("Unknown tool: {0}")]
    UnknownTool(String),
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Tool execution failed: {0}")]
    ToolExecution(String),
}

/// Persistent metadata for tracking sessions across process boundaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: String,
    pub workspace_path: String,
    pub created_at_rfc3339: String,
    pub checkpoints: Vec<agentkernel_fs::Checkpoint>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

pub fn session_store_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("agentkernel_sessions");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn save_session_metadata(meta: &SessionMetadata) {
    let path = session_store_dir().join(format!("{}.json", meta.session_id));
    if let Ok(json) = serde_json::to_string_pretty(meta) {
        let _ = std::fs::write(path, json);
    }
}

pub fn load_session_metadata(session_id: &str) -> Option<SessionMetadata> {
    let path = session_store_dir().join(format!("{}.json", session_id));
    if let Ok(content) = std::fs::read_to_string(path) {
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

pub fn update_session_checkpoint(session_id: &str, cp: &agentkernel_fs::Checkpoint) {
    if let Some(mut meta) = load_session_metadata(session_id) {
        meta.checkpoints.retain(|c| c.id != cp.id);
        meta.checkpoints.push(cp.clone());
        save_session_metadata(&meta);
    }
}

pub fn remove_session_metadata(session_id: &str) {
    let path = session_store_dir().join(format!("{}.json", session_id));
    let _ = std::fs::remove_file(path);
}

/// Active session tracking within the MCP server
pub struct ActiveSessionRecord {
    pub session: Arc<dyn SandboxSession>,
    pub workspace_path: PathBuf,
    pub config: SandboxConfig,
    pub created_at: std::time::Instant,
    pub checkpoints: Arc<RwLock<Vec<agentkernel_fs::Checkpoint>>>,
    pub total_cpu_time_ms: Arc<AtomicU64>,
    pub stream_tx: broadcast::Sender<String>,
    pub tenant_id: Option<TenantId>,
}

/// High-Performance Model Context Protocol Server for AgentKernel.
pub struct AgentKernelMcpServer {
    pool_manager: Arc<dyn PoolManager>,
    sessions: Arc<RwLock<HashMap<String, ActiveSessionRecord>>>,
    tenant_manager: Arc<TenantManager>,
    metrics: Arc<MetricsRegistry>,
    require_auth: bool,
}

#[async_trait]
pub trait McpServer: Send + Sync {
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse;
    async fn run_stdio(&self) -> Result<(), McpError>;
}

impl AgentKernelMcpServer {
    pub fn new(pool_manager: Arc<dyn PoolManager>) -> Self {
        let metrics = Arc::new(MetricsRegistry::new());
        let tenant_manager = Arc::new(TenantManager::with_metrics(metrics.clone()));
        Self {
            pool_manager,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            tenant_manager,
            metrics,
            require_auth: false,
        }
    }

    /// Convenience constructor with a local pool manager
    pub fn with_local_pool(warm_pool_size: usize) -> Self {
        let pool = Arc::new(LocalPoolManager::new(warm_pool_size));
        Self::new(pool)
    }

    /// Creates an MCP server with a specific TenantManager and enforced authentication.
    pub fn with_tenant_manager(
        pool_manager: Arc<dyn PoolManager>,
        tenant_manager: Arc<TenantManager>,
    ) -> Self {
        let metrics = Arc::new(MetricsRegistry::new());
        Self {
            pool_manager,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            tenant_manager,
            metrics,
            require_auth: true,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn require_auth(mut self, require: bool) -> Self {
        self.require_auth = require;
        self
    }

    pub fn tenant_manager(&self) -> &Arc<TenantManager> {
        &self.tenant_manager
    }

    pub fn metrics(&self) -> &Arc<MetricsRegistry> {
        &self.metrics
    }

    pub fn render_prometheus_metrics(&self) -> String {
        self.metrics.render_prometheus_metrics()
    }

    pub async fn is_auth_enforced(&self) -> bool {
        self.require_auth || self.tenant_manager.has_tenants().await
    }

    /// Primary JSON-RPC 2.0 request dispatcher
    pub async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        self.handle_request_with_tenant(req, None).await
    }

    /// Primary JSON-RPC 2.0 request dispatcher with optional authenticated tenant context
    pub async fn handle_request_with_tenant(
        &self,
        req: JsonRpcRequest,
        tenant_override: Option<TenantId>,
    ) -> JsonRpcResponse {
        let req_id = req.id.clone();

        // Determine effective tenant
        let caller_tenant = if let Some(t) = tenant_override {
            Some(t)
        } else if let Some(ref params) = req.params {
            // Check if api_key or auth_token is provided in request params
            let api_key = params
                .get("api_key")
                .or_else(|| params.get("auth_token"))
                .and_then(|v| v.as_str());

            if let Some(key) = api_key {
                match self.tenant_manager.authenticate_key(key).await {
                    Ok(t) => Some(t.tenant_id),
                    Err(_) => {
                        return JsonRpcResponse::error(
                            req_id,
                            JsonRpcError::unauthorized("Unauthorized: Invalid API key"),
                        );
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // If auth is enforced and caller tenant is not established:
        // Allow MCP metadata methods (initialize, ping, tools/list) but reject stateful tools/call
        if self.is_auth_enforced().await && caller_tenant.is_none() && req.method == "tools/call" {
            return JsonRpcResponse::error(
                req_id,
                JsonRpcError::unauthorized("Unauthorized: Authentication required"),
            );
        }

        match req.method.as_str() {
            "initialize" => {
                let init_result = InitializeResult {
                    protocol_version: "2024-11-05".to_string(),
                    capabilities: ServerCapabilities {
                        tools: Some(ToolsCapability { list_changed: false }),
                    },
                    server_info: ServerInfo {
                        name: "agentkernel".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                };
                JsonRpcResponse::success(req_id, json!(init_result))
            }
            "notifications/initialized" => {
                info!("MCP client initialized session");
                JsonRpcResponse::success(req_id, json!({}))
            }
            "ping" => JsonRpcResponse::success(req_id, json!({})),
            "tools/list" => {
                let tools = mcp_tools_list();
                JsonRpcResponse::success(req_id, json!({ "tools": tools }))
            }
            "tools/call" => {
                let params = match req.params {
                    Some(Value::Object(map)) => map,
                    _ => {
                        return JsonRpcResponse::error(
                            req_id,
                            JsonRpcError::invalid_params("Expected object with 'name' and 'arguments'"),
                        );
                    }
                };

                let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => {
                        return JsonRpcResponse::error(
                            req_id,
                            JsonRpcError::invalid_params("Missing required 'name' string"),
                        );
                    }
                };

                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));

                let tool_result = self
                    .execute_tool(tool_name, arguments, caller_tenant.as_ref())
                    .await;
                JsonRpcResponse::success(req_id, json!(tool_result))
            }
            unknown => {
                warn!("Received unknown MCP method: {}", unknown);
                JsonRpcResponse::error(
                    req_id,
                    JsonRpcError::method_not_found(format!("Method not found: {unknown}")),
                )
            }
        }
    }

    /// Validates tenant ownership of a session. If ownership is violated, returns CallToolResult error.
    async fn check_session_access(
        &self,
        session_id: &str,
        caller_tenant: Option<&TenantId>,
    ) -> Result<(), CallToolResult> {
        let caller = match caller_tenant {
            Some(t) => t,
            None => return Ok(()),
        };

        // 1. Check in-memory session records
        let sessions = self.sessions.read().await;
        if let Some(record) = sessions.get(session_id) {
            if let Some(ref owner) = record.tenant_id {
                if owner != caller {
                    return Err(CallToolResult::error(format!(
                        "Unauthorized: Sandbox session '{session_id}' does not belong to tenant '{caller}'"
                    )));
                }
            }
            return Ok(());
        }

        // 2. Check metadata on disk
        if let Some(meta) = load_session_metadata(session_id) {
            if let Some(ref owner) = meta.tenant_id {
                if owner != caller.as_str() {
                    return Err(CallToolResult::error(format!(
                        "Unauthorized: Sandbox session '{session_id}' does not belong to tenant '{caller}'"
                    )));
                }
            }
            return Ok(());
        }

        // 3. Check TenantManager session map
        if let Some(owner) = self.tenant_manager.get_session_owner(session_id).await {
            if &owner != caller {
                return Err(CallToolResult::error(format!(
                    "Unauthorized: Sandbox session '{session_id}' does not belong to tenant '{caller}'"
                )));
            }
            return Ok(());
        }

        Err(CallToolResult::error(format!(
            "Sandbox session '{session_id}' not found"
        )))
    }

    /// Dispatches execution of the supported sandbox tools
    async fn execute_tool(
        &self,
        name: &str,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        match name {
            "sandbox_acquire" => self.tool_acquire(args, caller_tenant).await,
            "sandbox_exec" => self.tool_exec(args, caller_tenant).await,
            "sandbox_read_file" => self.tool_read_file(args, caller_tenant).await,
            "sandbox_write_patch" => self.tool_write_patch(args, caller_tenant).await,
            "sandbox_create_checkpoint" => self.tool_create_checkpoint(args, caller_tenant).await,
            "sandbox_rollback" => self.tool_rollback(args, caller_tenant).await,
            "sandbox_release" => self.tool_release(args, caller_tenant).await,
            "sandbox_diff" => self.tool_diff(args, caller_tenant).await,
            "sandbox_list_checkpoints" => self.tool_list_checkpoints(args, caller_tenant).await,
            "sandbox_metrics" => self.tool_metrics(args, caller_tenant).await,
            unknown => CallToolResult::error(format!("Unknown tool: '{unknown}'")),
        }
    }

    async fn tool_acquire(&self, args: Value, caller_tenant: Option<&TenantId>) -> CallToolResult {
        let workspace_path = match args.get("workspace_path").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return CallToolResult::error("Missing required parameter 'workspace_path'"),
        };

        let base_rootfs = args
            .get("base_rootfs")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut env_vars = Vec::new();
        if let Some(Value::Object(env_map)) = args.get("env_vars") {
            for (k, v) in env_map {
                if let Some(val_str) = v.as_str() {
                    env_vars.push((k.clone(), val_str.to_string()));
                }
            }
        }

        let timeout_seconds = args
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(300);
        let session_id = format!("session-{}", Uuid::new_v4());

        // Determine effective tenant_id
        let effective_tenant_id = caller_tenant.cloned().or_else(|| {
            args.get("tenant_id")
                .and_then(|v| v.as_str())
                .map(TenantId::new)
        });

        // Enforce quota if tenant is determined
        if let Some(ref tid) = effective_tenant_id {
            if let Err(e) = self.tenant_manager.acquire_sandbox_lease(tid, &session_id).await {
                return CallToolResult::error(format!("Quota exceeded: {e}"));
            }
        }

        let config = SandboxConfig {
            session_id: session_id.clone(),
            tenant_id: effective_tenant_id.as_ref().map(|t| t.0.clone()),
            workspace_path: workspace_path.clone(),
            base_rootfs,
            env_vars,
            timeout_seconds,
        };

        match self.pool_manager.acquire_sandbox(config.clone()).await {
            Ok(session) => {
                let (stream_tx, _) = broadcast::channel(256);
                let record = ActiveSessionRecord {
                    session,
                    workspace_path: PathBuf::from(&workspace_path),
                    config,
                    created_at: std::time::Instant::now(),
                    checkpoints: Arc::new(RwLock::new(Vec::new())),
                    total_cpu_time_ms: Arc::new(AtomicU64::new(0)),
                    stream_tx,
                    tenant_id: effective_tenant_id.clone(),
                };
                self.sessions
                    .write()
                    .await
                    .insert(session_id.clone(), record);

                save_session_metadata(&SessionMetadata {
                    session_id: session_id.clone(),
                    workspace_path: workspace_path.clone(),
                    created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
                    checkpoints: Vec::new(),
                    tenant_id: effective_tenant_id.as_ref().map(|t| t.0.clone()),
                });

                CallToolResult::success_json(&json!({
                    "session_id": session_id,
                    "workspace_path": workspace_path,
                    "status": "leased",
                    "tenant_id": effective_tenant_id.as_ref().map(|t| t.0.clone())
                }))
            }
            Err(e) => {
                if let Some(ref tid) = effective_tenant_id {
                    self.tenant_manager
                        .release_sandbox_lease(tid, &session_id)
                        .await;
                }
                CallToolResult::error(format!("Failed to acquire sandbox: {e}"))
            }
        }
    }

    async fn tool_exec(&self, args: Value, caller_tenant: Option<&TenantId>) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let cmd = match args.get("cmd").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'cmd'"),
        };

        let cmd_args: Vec<String> = args
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let timeout_ms = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(30_000);

        let (session, stream_tx, total_cpu) = {
            let sessions = self.sessions.read().await;
            let record = match sessions.get(session_id) {
                Some(r) => r,
                None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
            };
            (
                record.session.clone(),
                record.stream_tx.clone(),
                record.total_cpu_time_ms.clone(),
            )
        };

        let _ = stream_tx.send(
            json!({
                "event": "exec_start",
                "cmd": cmd,
                "args": cmd_args,
            })
            .to_string(),
        );

        match session.exec(cmd, &cmd_args, timeout_ms).await {
            Ok(output) => {
                self.metrics.commands_total.inc();
                total_cpu.fetch_add(output.duration_ms, Ordering::Relaxed);
                if !output.stdout.is_empty() {
                    let _ = stream_tx.send(
                        json!({
                            "event": "stdout",
                            "data": output.stdout,
                        })
                        .to_string(),
                    );
                }
                if !output.stderr.is_empty() {
                    let _ = stream_tx.send(
                        json!({
                            "event": "stderr",
                            "data": output.stderr,
                        })
                        .to_string(),
                    );
                }
                let _ = stream_tx.send(
                    json!({
                        "event": "exec_end",
                        "exit_code": output.exit_code,
                        "duration_ms": output.duration_ms,
                    })
                    .to_string(),
                );

                CallToolResult::success_json(&json!({
                    "exit_code": output.exit_code,
                    "stdout": output.stdout,
                    "stderr": output.stderr,
                    "duration_ms": output.duration_ms
                }))
            }
            Err(e) => {
                let _ = stream_tx.send(
                    json!({
                        "event": "exec_error",
                        "error": e.to_string(),
                    })
                    .to_string(),
                );
                CallToolResult::error(format!("Command execution failed: {e}"))
            }
        }
    }

    async fn tool_read_file(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let path = match args.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return CallToolResult::error("Missing required parameter 'path'"),
        };

        let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let limit = args.get("limit").and_then(|v| v.as_u64()).map(|v| v as usize);

        let workspace_path = {
            let sessions = self.sessions.read().await;
            if let Some(record) = sessions.get(session_id) {
                record.workspace_path.clone()
            } else if let Some(meta) = load_session_metadata(session_id) {
                PathBuf::from(meta.workspace_path)
            } else {
                return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
            }
        };

        let safe_target = match resolve_safe_path(&workspace_path, path) {
            Ok(p) => p,
            Err(e) => return CallToolResult::error(format!("Invalid path '{path}': {e}")),
        };

        match tokio::fs::read_to_string(&safe_target).await {
            Ok(content) => {
                if offset == 0 && limit.is_none() {
                    CallToolResult::success(content)
                } else {
                    let lines: Vec<&str> = content.lines().collect();
                    let start = if offset > 0 { offset.saturating_sub(1) } else { 0 };
                    let end = match limit {
                        Some(l) => (start + l).min(lines.len()),
                        None => lines.len(),
                    };
                    let sliced = lines[start..end].join("\n");
                    CallToolResult::success(sliced)
                }
            }
            Err(e) => CallToolResult::error(format!("Failed to read file '{path}': {e}")),
        }
    }

    async fn tool_write_patch(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let path = match args.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return CallToolResult::error("Missing required parameter 'path'"),
        };

        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'content'"),
        };

        let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(false);

        let workspace_path = {
            let sessions = self.sessions.read().await;
            if let Some(record) = sessions.get(session_id) {
                record.workspace_path.clone()
            } else if let Some(meta) = load_session_metadata(session_id) {
                PathBuf::from(meta.workspace_path)
            } else {
                return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
            }
        };

        let safe_target = match resolve_safe_path(&workspace_path, path) {
            Ok(p) => p,
            Err(e) => return CallToolResult::error(format!("Invalid path '{path}': {e}")),
        };

        if let Some(parent) = safe_target.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return CallToolResult::error(format!("Failed to create parent directories: {e}"));
            }
        }

        let write_res = if append {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&safe_target)
                .await
            {
                Ok(mut file) => file.write_all(content.as_bytes()).await,
                Err(e) => Err(e),
            }
        } else {
            tokio::fs::write(&safe_target, content.as_bytes()).await
        };

        match write_res {
            Ok(_) => CallToolResult::success_json(&json!({
                "success": true,
                "path": path,
                "bytes_written": content.len()
            })),
            Err(e) => CallToolResult::error(format!("Failed to write to file '{path}': {e}")),
        }
    }

    async fn tool_create_checkpoint(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return CallToolResult::error("Missing required parameter 'name'"),
        };

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        let t0 = std::time::Instant::now();
        match record.session.create_checkpoint(name).await {
            Ok(cp) => {
                self.metrics
                    .checkpoint_duration_seconds
                    .observe_duration(t0.elapsed());
                record.checkpoints.write().await.push(cp.clone());
                update_session_checkpoint(session_id, &cp);

                CallToolResult::success_json(&json!({
                    "checkpoint_id": cp.id,
                    "name": cp.name,
                    "created_at": cp.created_at,
                    "upperdir_path": cp.upperdir_path
                }))
            }
            Err(e) => CallToolResult::error(format!("Failed to create checkpoint: {e}")),
        }
    }

    async fn tool_rollback(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let checkpoint_id = match args.get("checkpoint_id").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'checkpoint_id'"),
        };

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        let t0 = std::time::Instant::now();
        match record.session.rollback(checkpoint_id).await {
            Ok(_) => {
                self.metrics
                    .rollback_duration_seconds
                    .observe_duration(t0.elapsed());
                CallToolResult::success_json(&json!({
                    "success": true,
                    "session_id": session_id,
                    "checkpoint_id": checkpoint_id
                }))
            }
            Err(e) => CallToolResult::error(format!("Failed to rollback: {e}")),
        }
    }

    async fn tool_release(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let removed = self.sessions.write().await.remove(session_id);
        if removed.is_none() {
            return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
        }

        remove_session_metadata(session_id);

        if let Some(tid) = caller_tenant {
            self.tenant_manager
                .release_sandbox_lease(tid, session_id)
                .await;
        } else {
            self.tenant_manager.release_session(session_id).await;
        }

        match self.pool_manager.release_sandbox(session_id).await {
            Ok(_) => CallToolResult::success_json(&json!({
                "success": true,
                "session_id": session_id,
                "status": "released"
            })),
            Err(e) => CallToolResult::error(format!("Failed to release sandbox: {e}")),
        }
    }

    async fn tool_diff(&self, args: Value, caller_tenant: Option<&TenantId>) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let from_cp_id = args.get("from_checkpoint").and_then(|v| v.as_str());
        let to_cp_id = args.get("to_checkpoint").and_then(|v| v.as_str());

        let (workspace_path, checkpoints) = {
            let sessions = self.sessions.read().await;
            if let Some(record) = sessions.get(session_id) {
                let cps = record.checkpoints.read().await.clone();
                (record.workspace_path.clone(), cps)
            } else if let Some(meta) = load_session_metadata(session_id) {
                (PathBuf::from(meta.workspace_path), meta.checkpoints)
            } else {
                return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
            }
        };

        // Determine from_dir
        let from_dir = match from_cp_id {
            Some(from_id) => {
                if let Some(cp) = checkpoints
                    .iter()
                    .find(|c| c.id == from_id || c.name == from_id)
                {
                    cp.upperdir_path.clone()
                } else {
                    let disk_path = workspace_path
                        .join(".agentkernel")
                        .join("checkpoints")
                        .join(from_id);
                    if disk_path.exists() {
                        disk_path
                    } else {
                        return CallToolResult::error(format!("Checkpoint '{from_id}' not found"));
                    }
                }
            }
            None => {
                if let Some(last_cp) = checkpoints.last() {
                    last_cp.upperdir_path.clone()
                } else {
                    workspace_path.clone()
                }
            }
        };

        // Determine to_dir
        let to_dir = match to_cp_id {
            Some(to_id) => {
                if let Some(cp) = checkpoints
                    .iter()
                    .find(|c| c.id == to_id || c.name == to_id)
                {
                    cp.upperdir_path.clone()
                } else {
                    let disk_path = workspace_path
                        .join(".agentkernel")
                        .join("checkpoints")
                        .join(to_id);
                    if disk_path.exists() {
                        disk_path
                    } else {
                        return CallToolResult::error(format!("Checkpoint '{to_id}' not found"));
                    }
                }
            }
            None => workspace_path.clone(),
        };

        match compute_directory_diff(&from_dir, &to_dir, &[".agentkernel"]) {
            Ok(diff) => CallToolResult::success_json(&json!({
                "files": diff.files,
                "diff": diff.diff,
            })),
            Err(e) => CallToolResult::error(format!("Failed to compute diff: {e}")),
        }
    }

    async fn tool_list_checkpoints(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let (workspace_path, mut checkpoints) = {
            let sessions = self.sessions.read().await;
            if let Some(record) = sessions.get(session_id) {
                let cps = record.checkpoints.read().await.clone();
                (record.workspace_path.clone(), cps)
            } else if let Some(meta) = load_session_metadata(session_id) {
                (PathBuf::from(meta.workspace_path), meta.checkpoints)
            } else {
                return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
            }
        };

        let disk_cp_dir = workspace_path.join(".agentkernel").join("checkpoints");
        if disk_cp_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&disk_cp_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let id = entry.file_name().to_string_lossy().to_string();
                        if !checkpoints.iter().any(|c| c.id == id) {
                            checkpoints.push(agentkernel_fs::Checkpoint {
                                id: id.clone(),
                                name: id,
                                created_at: chrono::Utc::now(),
                                upperdir_path: path,
                                parent_id: None,
                            });
                        }
                    }
                }
            }
        }

        let mut list = Vec::new();
        for cp in checkpoints {
            let size_bytes = compute_dir_size(&cp.upperdir_path);
            list.push(json!({
                "id": cp.id,
                "name": cp.name,
                "created_at": cp.created_at.to_rfc3339(),
                "size_bytes": size_bytes,
            }));
        }

        CallToolResult::success_json(&list)
    }

    async fn tool_metrics(
        &self,
        args: Value,
        caller_tenant: Option<&TenantId>,
    ) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        if let Err(err) = self.check_session_access(session_id, caller_tenant).await {
            return err;
        }

        let (workspace_path, uptime_seconds, cpu_time_ms) = {
            let sessions = self.sessions.read().await;
            if let Some(record) = sessions.get(session_id) {
                let uptime = record.created_at.elapsed().as_secs();
                let cpu = record.total_cpu_time_ms.load(Ordering::Relaxed);
                (record.workspace_path.clone(), uptime, cpu)
            } else if let Some(meta) = load_session_metadata(session_id) {
                let uptime = chrono::DateTime::parse_from_rfc3339(&meta.created_at_rfc3339)
                    .map(|dt| {
                        (chrono::Utc::now() - dt.with_timezone(&chrono::Utc))
                            .num_seconds()
                            .max(0) as u64
                    })
                    .unwrap_or(0);
                (PathBuf::from(meta.workspace_path), uptime, 0)
            } else {
                return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
            }
        };

        let ram_rss = get_process_rss_bytes();
        let disk_layer = {
            let dot_ak = workspace_path.join(".agentkernel");
            if dot_ak.exists() {
                compute_dir_size(&dot_ak)
            } else {
                compute_dir_size(&workspace_path)
            }
        };

        let metrics = SandboxMetrics {
            session_id: session_id.to_string(),
            status: "leased".to_string(),
            uptime_seconds,
            cpu_time_ms,
            ram_rss_bytes: ram_rss,
            disk_layer_bytes: disk_layer,
        };

        CallToolResult::success_json(&metrics)
    }

    /// Run the server loop reading lines from an async reader and writing JSON-RPC to writer
    pub async fn run_stream<R, W>(&self, mut reader: R, mut writer: W) -> Result<(), McpError>
    where
        R: AsyncBufRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                // EOF reached
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            debug!("MCP stdio incoming: {}", trimmed);

            let req: Result<JsonRpcRequest, serde_json::Error> = serde_json::from_str(trimmed);
            match req {
                Ok(rpc_req) => {
                    let has_id = rpc_req.id.is_some();
                    let response = self.handle_request(rpc_req).await;

                    // Only send response if request was not a notification
                    if has_id {
                        let json_line = serde_json::to_string(&response)
                            .map_err(|e| McpError::JsonRpc(e.to_string()))?;
                        writer.write_all(json_line.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        writer.flush().await?;
                    }
                }
                Err(e) => {
                    let err_resp = JsonRpcResponse::error(
                        None,
                        JsonRpcError::parse_error(format!("Invalid JSON-RPC payload: {e}")),
                    );
                    let json_line = serde_json::to_string(&err_resp)
                        .map_err(|e| McpError::JsonRpc(e.to_string()))?;
                    writer.write_all(json_line.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
            }
        }

        Ok(())
    }

    /// Start MCP server over stdio
    pub async fn run_stdio(&self) -> Result<(), McpError> {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let stdout = tokio::io::stdout();
        self.run_stream(stdin, stdout).await
    }

    /// Start MCP HTTP/SSE server on the specified address
    pub async fn run_http_sse(&self, addr: &str) -> Result<(), McpError> {
        let listener = TcpListener::bind(addr).await?;
        info!("AgentKernel MCP HTTP/SSE server listening on http://{}", addr);

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            debug!("Accepted connection from {}", peer_addr);

            // Handle connection in background
            let server_ref = self.clone_handle();
            tokio::spawn(async move {
                if let Err(e) = handle_http_connection(server_ref, &mut socket).await {
                    error!("Error handling HTTP connection: {e}");
                }
            });
        }
    }

    fn clone_handle(&self) -> Arc<Self> {
        Arc::new(Self {
            pool_manager: self.pool_manager.clone(),
            sessions: self.sessions.clone(),
            tenant_manager: self.tenant_manager.clone(),
            metrics: self.metrics.clone(),
            require_auth: self.require_auth,
        })
    }
}

#[async_trait]
impl McpServer for AgentKernelMcpServer {
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        self.handle_request(req).await
    }

    async fn run_stdio(&self) -> Result<(), McpError> {
        self.run_stdio().await
    }
}

/// Lightweight HTTP/SSE connection handler supporting JSON-RPC POST, SSE streaming, and Prometheus metrics
async fn handle_http_connection(
    server: Arc<AgentKernelMcpServer>,
    socket: &mut tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = tokio::io::BufReader::new(reader);

    let mut request_line = String::new();
    if buf_reader.read_line(&mut request_line).await? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let uri = parts[1];

    let mut content_length = 0usize;
    let mut auth_header: Option<String> = None;

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
            let val = v.trim();
            if key == "content-length" {
                if let Ok(len) = val.parse::<usize>() {
                    content_length = len;
                }
            } else if key == "authorization" {
                auth_header = Some(val.to_string());
            }
        }
    }

    // CORS pre-flight
    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                    Access-Control-Allow-Headers: Content-Type, Authorization\r\n\r\n";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Prometheus metrics endpoint: GET /metrics
    if method == "GET" && uri == "/metrics" {
        let metrics_text = server.render_prometheus_metrics();
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\r\n\
             {}",
            metrics_text.len(),
            metrics_text
        );
        writer.write_all(resp.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // Tenant authentication validation
    let auth_enforced = server.is_auth_enforced().await;
    let authenticated_tenant: Option<TenantId> = if auth_enforced {
        let token = match auth_header.as_deref() {
            Some(header) => {
                let trimmed = header.trim();
                if let Some(token) = trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| trimmed.strip_prefix("bearer "))
                {
                    token.trim()
                } else {
                    let err_body = serde_json::to_vec(&JsonRpcResponse::error(
                        None,
                        JsonRpcError::unauthorized(
                            "Unauthorized: Invalid Authorization header format, expected 'Bearer <token>'",
                        ),
                    ))?;
                    let resp = format!(
                        "HTTP/1.1 401 Unauthorized\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Access-Control-Allow-Origin: *\r\n\r\n",
                        err_body.len()
                    );
                    writer.write_all(resp.as_bytes()).await?;
                    writer.write_all(&err_body).await?;
                    writer.flush().await?;
                    return Ok(());
                }
            }
            None => {
                let err_body = serde_json::to_vec(&JsonRpcResponse::error(
                    None,
                    JsonRpcError::unauthorized("Unauthorized: Missing Authorization header"),
                ))?;
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Access-Control-Allow-Origin: *\r\n\r\n",
                    err_body.len()
                );
                writer.write_all(resp.as_bytes()).await?;
                writer.write_all(&err_body).await?;
                writer.flush().await?;
                return Ok(());
            }
        };

        match server.tenant_manager.authenticate_key(token).await {
            Ok(tenant_cfg) => Some(tenant_cfg.tenant_id),
            Err(_) => {
                let err_body = serde_json::to_vec(&JsonRpcResponse::error(
                    None,
                    JsonRpcError::unauthorized("Unauthorized: Invalid API key"),
                ))?;
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Access-Control-Allow-Origin: *\r\n\r\n",
                    err_body.len()
                );
                writer.write_all(resp.as_bytes()).await?;
                writer.write_all(&err_body).await?;
                writer.flush().await?;
                return Ok(());
            }
        }
    } else {
        if let Some(header) = auth_header.as_deref() {
            let trimmed = header.trim();
            if let Some(token) = trimmed
                .strip_prefix("Bearer ")
                .or_else(|| trimmed.strip_prefix("bearer "))
            {
                server
                    .tenant_manager
                    .authenticate_key(token.trim())
                    .await
                    .ok()
                    .map(|t| t.tenant_id)
            } else {
                None
            }
        } else {
            None
        }
    };

    // SSE endpoint
    if method == "GET" && uri.starts_with("/sse") {
        let header = "HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Cache-Control: no-cache\r\n\
                      Connection: keep-alive\r\n\
                      Access-Control-Allow-Origin: *\r\n\r\n\
                      event: endpoint\r\ndata: /message\r\n\r\n";
        writer.write_all(header.as_bytes()).await?;
        writer.flush().await?;

        // Keep SSE connection open with periodic pings
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

    // Sandbox output stream endpoint: GET /sandbox/:id/stream
    if method == "GET" && uri.starts_with("/sandbox/") && uri.ends_with("/stream") {
        let parts: Vec<&str> = uri.split('/').collect();
        // uri format: /sandbox/<id>/stream -> parts: ["", "sandbox", "<id>", "stream"]
        if parts.len() >= 4 {
            let session_id = parts[2];

            // Validate tenant session ownership if authenticated
            if let Some(ref tid) = authenticated_tenant {
                let owner = {
                    let sessions = server.sessions.read().await;
                    sessions.get(session_id).and_then(|r| r.tenant_id.clone())
                };
                if let Some(ref owner_tid) = owner {
                    if owner_tid != tid {
                        let err_body = serde_json::to_vec(&JsonRpcResponse::error(
                            None,
                            JsonRpcError::unauthorized(format!(
                                "Unauthorized: Session '{session_id}' not owned by caller tenant"
                            )),
                        ))?;
                        let unauthorized = format!(
                            "HTTP/1.1 401 Unauthorized\r\n\
                             Content-Type: application/json\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Content-Length: {}\r\n\r\n",
                            err_body.len()
                        );
                        writer.write_all(unauthorized.as_bytes()).await?;
                        writer.write_all(&err_body).await?;
                        writer.flush().await?;
                        return Ok(());
                    }
                }
            }

            let rx_opt = {
                let sessions = server.sessions.read().await;
                sessions.get(session_id).map(|r| r.stream_tx.subscribe())
            };

            match rx_opt {
                Some(mut rx) => {
                    let header = "HTTP/1.1 200 OK\r\n\
                                  Content-Type: text/event-stream\r\n\
                                  Cache-Control: no-cache\r\n\
                                  Connection: keep-alive\r\n\
                                  Access-Control-Allow-Origin: *\r\n\r\n";
                    writer.write_all(header.as_bytes()).await?;
                    writer.flush().await?;

                    let init_event = format!(
                        "event: connected\r\ndata: {}\r\n\r\n",
                        json!({ "session_id": session_id, "status": "streaming" })
                    );
                    writer.write_all(init_event.as_bytes()).await?;
                    writer.flush().await?;

                    let mut ping_interval =
                        tokio::time::interval(std::time::Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            msg_res = rx.recv() => {
                                match msg_res {
                                    Ok(msg) => {
                                        let sse_chunk = format!("event: output\r\ndata: {}\r\n\r\n", msg);
                                        if writer.write_all(sse_chunk.as_bytes()).await.is_err() {
                                            break;
                                        }
                                        if writer.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                    Err(_) => break,
                                }
                            }
                            _ = ping_interval.tick() => {
                                if writer.write_all(b": ping\r\n\r\n").await.is_err() {
                                    break;
                                }
                                if writer.flush().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    return Ok(());
                }
                None => {
                    let not_found = "HTTP/1.1 404 Not Found\r\n\
                                     Content-Type: application/json\r\n\
                                     Access-Control-Allow-Origin: *\r\n\
                                     Content-Length: 39\r\n\r\n\
                                     {\"error\":\"Sandbox session not found\"}\n";
                    writer.write_all(not_found.as_bytes()).await?;
                    writer.flush().await?;
                    return Ok(());
                }
            }
        }
    }

    // JSON-RPC HTTP POST handling (/message, /mcp, /)
    if method == "POST" {
        let mut body = vec![0u8; content_length];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;

        let rpc_req: Result<JsonRpcRequest, _> = serde_json::from_slice(&body);
        let resp_body = match rpc_req {
            Ok(req) => {
                let res = server
                    .handle_request_with_tenant(req, authenticated_tenant)
                    .await;
                serde_json::to_vec(&res)?
            }
            Err(e) => {
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

    // Default 404 for unknown endpoints
    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    writer.write_all(not_found.as_bytes()).await?;
    Ok(())
}
