//! Multi-Tenant End-to-End Integration & Security Test Suite for AgentKernel.
//! Verifies:
//! 1. Quota Enforcement (max_concurrent_sandboxes per tenant, QuotaExceeded errors, replenishment).
//! 2. Cross-Tenant Isolation (tenant-beta cannot execute commands, rollback, or diff tenant-alpha's sandboxes).
//! 3. Authentication Security (Bearer token verification, 401 Unauthorized on invalid/missing credentials).

use agentkernel_core::tenant::{TenantConfig, TenantId, TenantManager};
use agentkernel_core::CoreError;
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::protocol::{JsonRpcError, JsonRpcRequest};
use agentkernel_mcp::server::AgentKernelMcpServer;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper to allocate an ephemeral TCP port for testing HTTP servers.
async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Failed to get local addr").port();
    drop(listener);
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

// ============================================================================
// Test 1: Quota Enforcement (Direct & MCP Levels)
// ============================================================================

#[tokio::test]
async fn test_quota_enforcement_core_direct() {
    let tenant_manager = Arc::new(TenantManager::new());

    // Setup 2 tenants:
    // tenant-alpha: quota = 2 concurrent sandboxes
    // tenant-beta: quota = 1 concurrent sandbox
    let alpha_cfg = TenantConfig::new("tenant-alpha", "Tenant Alpha Corp", "key-alpha-123", 2);
    let beta_cfg = TenantConfig::new("tenant-beta", "Tenant Beta Ltd", "key-beta-456", 1);

    tenant_manager.register_tenant(alpha_cfg).await.expect("Register alpha");
    tenant_manager.register_tenant(beta_cfg).await.expect("Register beta");

    let tid_alpha = TenantId::new("tenant-alpha");
    let tid_beta = TenantId::new("tenant-beta");

    // 1. tenant-alpha leases 2 sandboxes successfully
    tenant_manager
        .acquire_sandbox_lease(&tid_alpha, "alpha-sb-1")
        .await
        .expect("Alpha lease sb 1");
    assert_eq!(tenant_manager.active_sandbox_count(&tid_alpha).await, 1);

    tenant_manager
        .acquire_sandbox_lease(&tid_alpha, "alpha-sb-2")
        .await
        .expect("Alpha lease sb 2");
    assert_eq!(tenant_manager.active_sandbox_count(&tid_alpha).await, 2);

    // 2. Attempt to lease 3rd sandbox is rejected with QuotaExceeded
    let third_attempt = tenant_manager.acquire_sandbox_lease(&tid_alpha, "alpha-sb-3").await;
    match third_attempt {
        Err(CoreError::QuotaExceeded(msg)) => {
            assert!(
                msg.contains("quota"),
                "Expected quota exceeded error message, got: {msg}"
            );
        }
        other => panic!("Expected CoreError::QuotaExceeded, got: {:?}", other),
    }
    assert_eq!(tenant_manager.active_sandbox_count(&tid_alpha).await, 2);

    // 3. Release 1 sandbox for tenant-alpha
    tenant_manager
        .release_sandbox_lease(&tid_alpha, "alpha-sb-1")
        .await;
    assert_eq!(tenant_manager.active_sandbox_count(&tid_alpha).await, 1);

    // 4. Repeated lease of 3rd sandbox now succeeds
    tenant_manager
        .acquire_sandbox_lease(&tid_alpha, "alpha-sb-3")
        .await
        .expect("Alpha lease sb 3 after release");
    assert_eq!(tenant_manager.active_sandbox_count(&tid_alpha).await, 2);

    // 5. Test tenant-beta quota enforcement (limit: 1)
    tenant_manager
        .acquire_sandbox_lease(&tid_beta, "beta-sb-1")
        .await
        .expect("Beta lease sb 1");
    assert_eq!(tenant_manager.active_sandbox_count(&tid_beta).await, 1);

    let beta_second = tenant_manager.acquire_sandbox_lease(&tid_beta, "beta-sb-2").await;
    assert!(
        matches!(beta_second, Err(CoreError::QuotaExceeded(_))),
        "Tenant beta must be constrained to 1 sandbox"
    );

    // Clean up
    tenant_manager.release_sandbox_lease(&tid_beta, "beta-sb-1").await;
    assert_eq!(tenant_manager.active_sandbox_count(&tid_beta).await, 0);
}

#[tokio::test]
async fn test_quota_enforcement_mcp_rpc() {
    let tmp = tempdir().expect("tempdir");
    let ws = tmp.path().to_str().unwrap().to_string();

    let pool = Arc::new(LocalPoolManager::new(5));
    let tenant_manager = Arc::new(TenantManager::new());

    // Register tenant-alpha with quota = 2
    tenant_manager
        .register_tenant(TenantConfig::new(
            "tenant-alpha",
            "Alpha Corp",
            "key-alpha",
            2,
        ))
        .await
        .unwrap();

    let server = AgentKernelMcpServer::with_tenant_manager(pool, tenant_manager);

    // 1. First lease for tenant-alpha
    let req1 = JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": ws,
                "tenant_id": "tenant-alpha"
            },
            "api_key": "key-alpha"
        })),
    );
    let resp1 = server.handle_request(req1).await;
    let res1_val = resp1.result.expect("Acquire 1 result");
    assert_eq!(res1_val["isError"], json!(null));
    let txt1 = res1_val["content"][0]["text"].as_str().unwrap();
    let data1: serde_json::Value = serde_json::from_str(txt1).unwrap();
    let sb1_id = data1["session_id"].as_str().unwrap().to_string();
    assert_eq!(data1["status"], "leased");

    // 2. Second lease for tenant-alpha
    let req2 = JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": ws,
                "tenant_id": "tenant-alpha"
            },
            "api_key": "key-alpha"
        })),
    );
    let resp2 = server.handle_request(req2).await;
    let res2_val = resp2.result.expect("Acquire 2 result");
    assert_eq!(res2_val["isError"], json!(null));

    // 3. Third lease attempt must be rejected with QuotaExceeded
    let req3 = JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": ws,
                "tenant_id": "tenant-alpha"
            },
            "api_key": "key-alpha"
        })),
    );
    let resp3 = server.handle_request(req3).await;
    let res3_val = resp3.result.expect("Acquire 3 result");
    assert_eq!(
        res3_val["isError"],
        json!(true),
        "Third acquire must return error due to quota"
    );
    let err_txt = res3_val["content"][0]["text"].as_str().unwrap();
    assert!(
        err_txt.contains("Quota exceeded"),
        "Error message must indicate Quota exceeded: {err_txt}"
    );

    // 4. Release first sandbox
    let req_rel = JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": {
                "session_id": sb1_id,
                "tenant_id": "tenant-alpha"
            },
            "api_key": "key-alpha"
        })),
    );
    let resp_rel = server.handle_request(req_rel).await;
    assert_eq!(resp_rel.result.unwrap()["isError"], json!(null));

    // 5. Now third lease attempt succeeds
    let req3_retry = JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": ws,
                "tenant_id": "tenant-alpha"
            },
            "api_key": "key-alpha"
        })),
    );
    let resp3_retry = server.handle_request(req3_retry).await;
    let res3_retry_val = resp3_retry.result.expect("Acquire 3 retry result");
    assert_eq!(res3_retry_val["isError"], json!(null));
}

// ============================================================================
// Test 2: Cross-Tenant Isolation
// ============================================================================

#[tokio::test]
async fn test_cross_tenant_isolation_mcp() {
    let tmp = tempdir().expect("tempdir");
    let ws = tmp.path().to_str().unwrap().to_string();

    let pool = Arc::new(LocalPoolManager::new(5));
    let tenant_manager = Arc::new(TenantManager::new());

    tenant_manager
        .register_tenant(TenantConfig::new(
            "tenant-alpha",
            "Alpha Corp",
            "key-alpha",
            5,
        ))
        .await
        .unwrap();

    tenant_manager
        .register_tenant(TenantConfig::new("tenant-beta", "Beta Ltd", "key-beta", 5))
        .await
        .unwrap();

    let server = AgentKernelMcpServer::with_tenant_manager(pool, tenant_manager);

    // 1. tenant-alpha acquires sandbox
    let tid_alpha = TenantId::new("tenant-alpha");
    let tid_beta = TenantId::new("tenant-beta");

    let req_acq = JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": ws,
                "tenant_id": "tenant-alpha"
            }
        })),
    );
    let resp_acq = server.handle_request_with_tenant(req_acq, Some(tid_alpha.clone())).await;
    let res_acq = resp_acq.result.expect("Acquire result");
    let txt_acq = res_acq["content"][0]["text"].as_str().unwrap();
    let val_acq: serde_json::Value = serde_json::from_str(txt_acq).unwrap();
    let alpha_session_id = val_acq["session_id"].as_str().unwrap().to_string();

    // 2. tenant-alpha creates file and checkpoint
    let req_write = JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": alpha_session_id,
                "path": "alpha_secret.txt",
                "content": "confidential data for tenant-alpha"
            }
        })),
    );
    let resp_write = server.handle_request_with_tenant(req_write, Some(tid_alpha.clone())).await;
    assert_eq!(resp_write.result.unwrap()["isError"], json!(null));

    let req_cp = JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": alpha_session_id,
                "name": "checkpoint-alpha-1"
            }
        })),
    );
    let resp_cp = server.handle_request_with_tenant(req_cp, Some(tid_alpha.clone())).await;
    let res_cp = resp_cp.result.unwrap();
    assert_eq!(res_cp["isError"], json!(null));
    let cp_txt = res_cp["content"][0]["text"].as_str().unwrap();
    let cp_val: serde_json::Value = serde_json::from_str(cp_txt).unwrap();
    let cp_id = cp_val["checkpoint_id"].as_str().unwrap().to_string();

    // 3. tenant-beta attempts CROSS-TENANT access:

    // 3a. tenant-beta attempts `exec` on alpha's sandbox -> Strictly Rejected
    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "hack".to_string()])
    } else {
        ("echo", vec!["hack".to_string()])
    };
    let req_exec_unauth = JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_exec",
            "arguments": {
                "session_id": alpha_session_id,
                "cmd": cmd,
                "args": args
            }
        })),
    );
    let resp_exec = server.handle_request_with_tenant(req_exec_unauth, Some(tid_beta.clone())).await;
    let res_exec = resp_exec.result.unwrap();
    assert_eq!(
        res_exec["isError"],
        json!(true),
        "Cross-tenant exec must return an error"
    );
    let err_msg = res_exec["content"][0]["text"].as_str().unwrap();
    assert!(
        err_msg.contains("Unauthorized") || err_msg.contains("not belong to tenant"),
        "Error must mention Unauthorized: {err_msg}"
    );

    // 3b. tenant-beta attempts `rollback` on alpha's sandbox -> Strictly Rejected
    let req_rb_unauth = JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_rollback",
            "arguments": {
                "session_id": alpha_session_id,
                "checkpoint_id": cp_id
            }
        })),
    );
    let resp_rb = server.handle_request_with_tenant(req_rb_unauth, Some(tid_beta.clone())).await;
    let res_rb = resp_rb.result.unwrap();
    assert_eq!(
        res_rb["isError"],
        json!(true),
        "Cross-tenant rollback must return an error"
    );
    let err_msg_rb = res_rb["content"][0]["text"].as_str().unwrap();
    assert!(
        err_msg_rb.contains("Unauthorized") || err_msg_rb.contains("not belong to tenant"),
        "Error must mention Unauthorized: {err_msg_rb}"
    );

    // 3c. tenant-beta attempts `diff` on alpha's sandbox -> Strictly Rejected
    let req_diff_unauth = JsonRpcRequest::new(
        Some(json!(6)),
        "tools/call",
        Some(json!({
            "name": "sandbox_diff",
            "arguments": {
                "session_id": alpha_session_id
            }
        })),
    );
    let resp_diff = server.handle_request_with_tenant(req_diff_unauth, Some(tid_beta.clone())).await;
    let res_diff = resp_diff.result.unwrap();
    assert_eq!(
        res_diff["isError"],
        json!(true),
        "Cross-tenant diff must return an error"
    );

    // 3d. tenant-beta attempts `read_file` on alpha's secret -> Strictly Rejected
    let req_read_unauth = JsonRpcRequest::new(
        Some(json!(7)),
        "tools/call",
        Some(json!({
            "name": "sandbox_read_file",
            "arguments": {
                "session_id": alpha_session_id,
                "path": "alpha_secret.txt"
            }
        })),
    );
    let resp_read = server.handle_request_with_tenant(req_read_unauth, Some(tid_beta.clone())).await;
    let res_read = resp_read.result.unwrap();
    assert_eq!(
        res_read["isError"],
        json!(true),
        "Cross-tenant read_file must return an error"
    );

    // 3e. tenant-beta attempts `release` on alpha's sandbox -> Strictly Rejected
    let req_rel_unauth = JsonRpcRequest::new(
        Some(json!(8)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": {
                "session_id": alpha_session_id
            }
        })),
    );
    let resp_rel = server.handle_request_with_tenant(req_rel_unauth, Some(tid_beta.clone())).await;
    let res_rel = resp_rel.result.unwrap();
    assert_eq!(
        res_rel["isError"],
        json!(true),
        "Cross-tenant release must return an error"
    );

    // 4. Verify tenant-alpha CAN still access its own sandbox
    let req_exec_auth = JsonRpcRequest::new(
        Some(json!(9)),
        "tools/call",
        Some(json!({
            "name": "sandbox_exec",
            "arguments": {
                "session_id": alpha_session_id,
                "cmd": cmd,
                "args": args
            }
        })),
    );
    let resp_exec_auth = server.handle_request_with_tenant(req_exec_auth, Some(tid_alpha.clone())).await;
    assert_eq!(resp_exec_auth.result.unwrap()["isError"], json!(null));
}

// ============================================================================
// Test 3: Authentication Security (HTTP & JSON-RPC)
// ============================================================================

#[tokio::test]
async fn test_authentication_security_http() {
    let port = find_available_port().await;
    let server_addr = format!("127.0.0.1:{port}");

    let pool = Arc::new(LocalPoolManager::new(2));
    let tenant_manager = Arc::new(TenantManager::new());

    tenant_manager
        .register_tenant(TenantConfig::new(
            "tenant-alpha",
            "Alpha Corp",
            "secret-token-alpha",
            2,
        ))
        .await
        .unwrap();

    let server = Arc::new(AgentKernelMcpServer::with_tenant_manager(pool, tenant_manager));
    let server_task = {
        let server_clone = server.clone();
        let addr_clone = server_addr.clone();
        tokio::spawn(async move {
            let _ = server_clone.run_http_sse(&addr_clone).await;
        })
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Helper to send HTTP request and read full response
    async fn send_http_request(
        addr: &str,
        method: &str,
        path: &str,
        auth_header: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to HTTP server");

        let mut req_str = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
        if let Some(auth) = auth_header {
            req_str.push_str(&format!("Authorization: {auth}\r\n"));
        }
        if let Some(b) = body {
            req_str.push_str("Content-Type: application/json\r\n");
            req_str.push_str(&format!("Content-Length: {}\r\n", b.len()));
            req_str.push_str("\r\n");
            req_str.push_str(b);
        } else {
            req_str.push_str("\r\n");
        }

        stream.write_all(req_str.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf_reader = tokio::io::BufReader::new(stream);
        let mut status_line = String::new();
        buf_reader.read_line(&mut status_line).await.unwrap();

        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);

        let mut response_body = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if buf_reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }

        if content_length > 0 {
            let mut buf = vec![0u8; content_length];
            buf_reader.read_exact(&mut buf).await.unwrap();
            response_body = String::from_utf8_lossy(&buf).to_string();
        }

        (status_code, response_body)
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": std::env::temp_dir().to_str().unwrap()
            }
        }
    })
    .to_string();

    // 1. Request WITHOUT Authorization header -> 401 Unauthorized
    let (code1, body1) = send_http_request(&server_addr, "POST", "/message", None, Some(&payload)).await;
    assert_eq!(code1, 401, "Missing Authorization header must return 401 Unauthorized");
    assert!(
        body1.contains("Unauthorized") || body1.contains("-32001"),
        "Response body must indicate unauthorized: {body1}"
    );

    // 2. Request with INVALID Bearer token -> 401 Unauthorized
    let (code2, body2) = send_http_request(
        &server_addr,
        "POST",
        "/message",
        Some("Bearer invalid-secret-token"),
        Some(&payload),
    )
    .await;
    assert_eq!(code2, 401, "Invalid Bearer token must return 401 Unauthorized");
    assert!(
        body2.contains("Unauthorized") || body2.contains("-32001"),
        "Response body must indicate unauthorized: {body2}"
    );

    // 3. Request with VALID Bearer token -> 200 OK
    let (code3, body3) = send_http_request(
        &server_addr,
        "POST",
        "/message",
        Some("Bearer secret-token-alpha"),
        Some(&payload),
    )
    .await;
    assert_eq!(code3, 200, "Valid Bearer token must return 200 OK");
    assert!(
        body3.contains("session_id"),
        "Response must contain acquired session: {body3}"
    );

    // 4. Prometheus metrics endpoint remains accessible (200 OK)
    let (code_met, body_met) = send_http_request(&server_addr, "GET", "/metrics", None, None).await;
    assert_eq!(code_met, 200, "Metrics endpoint must return 200 OK");
    assert!(
        body_met.contains("# HELP") && body_met.contains("# TYPE"),
        "Metrics must contain Prometheus format exposition"
    );

    server_task.abort();
}

#[tokio::test]
async fn test_authentication_security_rpc_direct() {
    let pool = Arc::new(LocalPoolManager::new(2));
    let tenant_manager = Arc::new(TenantManager::new());

    tenant_manager
        .register_tenant(TenantConfig::new(
            "tenant-alpha",
            "Alpha Corp",
            "ak-alpha-token-999",
            2,
        ))
        .await
        .unwrap();

    // Server with auth enforced
    let server = AgentKernelMcpServer::with_tenant_manager(pool, tenant_manager);

    // 1. Direct call without tenant and without api_key in enforced mode
    let req_unauth = JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": std::env::temp_dir().to_str().unwrap()
            }
        })),
    );
    let resp_unauth = server.handle_request(req_unauth).await;
    assert!(resp_unauth.error.is_some(), "Request must fail with error");
    let err = resp_unauth.error.unwrap();
    assert_eq!(
        err.code,
        JsonRpcError::UNAUTHORIZED,
        "Error code must be -32001 (Unauthorized)"
    );
    assert!(err.message.contains("Unauthorized"));

    // 2. Call with invalid api_key in params
    let req_invalid = JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": std::env::temp_dir().to_str().unwrap()
            },
            "api_key": "wrong-key"
        })),
    );
    let resp_invalid = server.handle_request(req_invalid).await;
    assert!(resp_invalid.error.is_some(), "Invalid key must fail");
    let err_inv = resp_invalid.error.unwrap();
    assert_eq!(err_inv.code, JsonRpcError::UNAUTHORIZED);

    // 3. Call with valid api_key in params -> Succeeds
    let req_valid = JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": {
                "workspace_path": std::env::temp_dir().to_str().unwrap()
            },
            "api_key": "ak-alpha-token-999"
        })),
    );
    let resp_valid = server.handle_request(req_valid).await;
    assert!(resp_valid.error.is_none(), "Valid key must succeed");
    assert!(resp_valid.result.is_some());
}
