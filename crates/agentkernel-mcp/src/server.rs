//! AgentKernel MCP Server (JSON-RPC 2.0 over stdio & HTTP/SSE).

use crate::local_pool::LocalPoolManager;
use crate::protocol::*;
use crate::tools::*;
use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::{SandboxConfig, SandboxSession};
use agentkernel_core::CoreError;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
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

/// Active session tracking within the MCP server
pub struct ActiveSessionRecord {
    pub session: Arc<dyn SandboxSession>,
    pub workspace_path: PathBuf,
    pub config: SandboxConfig,
}

/// High-Performance Model Context Protocol Server for AgentKernel.
pub struct AgentKernelMcpServer {
    pool_manager: Arc<dyn PoolManager>,
    sessions: Arc<RwLock<HashMap<String, ActiveSessionRecord>>>,
}

#[async_trait]
pub trait McpServer: Send + Sync {
    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse;
    async fn run_stdio(&self) -> Result<(), McpError>;
}

impl AgentKernelMcpServer {
    pub fn new(pool_manager: Arc<dyn PoolManager>) -> Self {
        Self {
            pool_manager,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Convenience constructor with a local pool manager
    pub fn with_local_pool(warm_pool_size: usize) -> Self {
        let pool = Arc::new(LocalPoolManager::new(warm_pool_size));
        Self::new(pool)
    }

    /// Primary JSON-RPC 2.0 request dispatcher
    pub async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let req_id = req.id.clone();
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

                let arguments = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));

                let tool_result = self.execute_tool(tool_name, arguments).await;
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

    /// Dispatches execution of the 7 supported sandbox tools
    async fn execute_tool(&self, name: &str, args: Value) -> CallToolResult {
        match name {
            "sandbox_acquire" => self.tool_acquire(args).await,
            "sandbox_exec" => self.tool_exec(args).await,
            "sandbox_read_file" => self.tool_read_file(args).await,
            "sandbox_write_patch" => self.tool_write_patch(args).await,
            "sandbox_create_checkpoint" => self.tool_create_checkpoint(args).await,
            "sandbox_rollback" => self.tool_rollback(args).await,
            "sandbox_release" => self.tool_release(args).await,
            unknown => CallToolResult::error(format!("Unknown tool: '{unknown}'")),
        }
    }

    async fn tool_acquire(&self, args: Value) -> CallToolResult {
        let workspace_path = match args.get("workspace_path").and_then(|v| v.as_str()) {
            Some(p) => p.to_string(),
            None => return CallToolResult::error("Missing required parameter 'workspace_path'"),
        };

        let base_rootfs = args.get("base_rootfs").and_then(|v| v.as_str()).map(|s| s.to_string());

        let mut env_vars = Vec::new();
        if let Some(Value::Object(env_map)) = args.get("env_vars") {
            for (k, v) in env_map {
                if let Some(val_str) = v.as_str() {
                    env_vars.push((k.clone(), val_str.to_string()));
                }
            }
        }

        let timeout_seconds = args.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300);
        let session_id = format!("session-{}", Uuid::new_v4());

        let config = SandboxConfig {
            session_id: session_id.clone(),
            workspace_path: workspace_path.clone(),
            base_rootfs,
            env_vars,
            timeout_seconds,
        };

        match self.pool_manager.acquire_sandbox(config.clone()).await {
            Ok(session) => {
                let record = ActiveSessionRecord {
                    session,
                    workspace_path: PathBuf::from(&workspace_path),
                    config,
                };
                self.sessions.write().await.insert(session_id.clone(), record);

                CallToolResult::success_json(&json!({
                    "session_id": session_id,
                    "workspace_path": workspace_path,
                    "status": "leased"
                }))
            }
            Err(e) => CallToolResult::error(format!("Failed to acquire sandbox: {e}")),
        }
    }

    async fn tool_exec(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let cmd = match args.get("cmd").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'cmd'"),
        };

        let cmd_args: Vec<String> = args
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let timeout_ms = args.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(30_000);

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        match record.session.exec(cmd, &cmd_args, timeout_ms).await {
            Ok(output) => CallToolResult::success_json(&output),
            Err(e) => CallToolResult::error(format!("Command execution failed: {e}")),
        }
    }

    async fn tool_read_file(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let path = match args.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return CallToolResult::error("Missing required parameter 'path'"),
        };

        let offset = args.get("offset").and_then(|v| v.as_u64()).map(|u| u as usize);
        let limit = args.get("limit").and_then(|v| v.as_u64()).map(|u| u as usize);

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        let safe_target = match resolve_safe_path(&record.workspace_path, path) {
            Ok(p) => p,
            Err(e) => return CallToolResult::error(e),
        };

        match tokio::fs::read_to_string(&safe_target).await {
            Ok(content) => {
                if offset.is_none() && limit.is_none() {
                    return CallToolResult::success(content);
                }

                let lines: Vec<&str> = content.lines().collect();
                let start_idx = offset.unwrap_or(1).saturating_sub(1);
                let selected: Vec<&str> = if let Some(lim) = limit {
                    lines.into_iter().skip(start_idx).take(lim).collect()
                } else {
                    lines.into_iter().skip(start_idx).collect()
                };

                CallToolResult::success(selected.join("\n"))
            }
            Err(e) => CallToolResult::error(format!("Failed to read file '{path}': {e}")),
        }
    }

    async fn tool_write_patch(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let path = match args.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return CallToolResult::error("Missing required parameter 'path'"),
        };

        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'content'"),
        };

        let append = args.get("append").and_then(|v| v.as_bool()).unwrap_or(false);

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        let safe_target = match resolve_safe_path(&record.workspace_path, path) {
            Ok(p) => p,
            Err(e) => return CallToolResult::error(e),
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

    async fn tool_create_checkpoint(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return CallToolResult::error("Missing required parameter 'name'"),
        };

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        match record.session.create_checkpoint(name).await {
            Ok(cp) => CallToolResult::success_json(&json!({
                "checkpoint_id": cp.id,
                "name": cp.name,
                "created_at": cp.created_at,
                "upperdir_path": cp.upperdir_path
            })),
            Err(e) => CallToolResult::error(format!("Failed to create checkpoint: {e}")),
        }
    }

    async fn tool_rollback(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let checkpoint_id = match args.get("checkpoint_id").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return CallToolResult::error("Missing required parameter 'checkpoint_id'"),
        };

        let sessions = self.sessions.read().await;
        let record = match sessions.get(session_id) {
            Some(r) => r,
            None => return CallToolResult::error(format!("Sandbox session '{session_id}' not found")),
        };

        match record.session.rollback(checkpoint_id).await {
            Ok(_) => CallToolResult::success_json(&json!({
                "success": true,
                "session_id": session_id,
                "checkpoint_id": checkpoint_id
            })),
            Err(e) => CallToolResult::error(format!("Failed to rollback: {e}")),
        }
    }

    async fn tool_release(&self, args: Value) -> CallToolResult {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return CallToolResult::error("Missing required parameter 'session_id'"),
        };

        let removed = self.sessions.write().await.remove(session_id);
        if removed.is_none() {
            return CallToolResult::error(format!("Sandbox session '{session_id}' not found"));
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

/// Lightweight HTTP/SSE connection handler supporting JSON-RPC POST and SSE streaming
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
            if k.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(len) = v.trim().parse::<usize>() {
                    content_length = len;
                }
            }
        }
    }

    // CORS pre-flight
    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                    Access-Control-Allow-Headers: Content-Type\r\n\r\n";
        writer.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

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

    // JSON-RPC HTTP POST handling (/message, /mcp, /)
    if method == "POST" {
        let mut body = vec![0u8; content_length];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;

        let rpc_req: Result<JsonRpcRequest, _> = serde_json::from_slice(&body);
        let resp_body = match rpc_req {
            Ok(req) => {
                let res = server.handle_request(req).await;
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
