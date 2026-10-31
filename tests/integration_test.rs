//! AgentKernel End-to-End Integration Test
//! Verifies complete lifecycle:
//! Pool initialization -> Sandbox leasing -> Command execution -> Checkpoint creation -> Rollback -> Release.

use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::SandboxConfig;
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::server::AgentKernelMcpServer;
use agentkernel_mcp::protocol::JsonRpcRequest;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_sandbox_lifecycle_direct() {
    let tmp = tempdir().expect("Failed to create temporary workspace");
    let workspace_path = tmp.path().to_str().unwrap().to_string();

    // 1. Initialize warm pool with 3 isolates
    let pool = Arc::new(LocalPoolManager::new(3));
    assert_eq!(pool.warm_count().await, 3);

    // 2. Lease sandbox isolate
    let config = SandboxConfig {
        session_id: "test-session-1".to_string(),
        workspace_path: workspace_path.clone(),
        base_rootfs: None,
        env_vars: vec![("AGENT_ENV".to_string(), "production".to_string())],
        timeout_seconds: 60,
    };
    let session = pool.acquire_sandbox(config).await.expect("Failed to acquire sandbox");
    assert_eq!(session.id(), "test-session-1");
    assert_eq!(pool.warm_count().await, 2);

    // Initial state: write baseline file
    let file1_path = tmp.path().join("code.rs");
    tokio::fs::write(&file1_path, b"fn main() { println!(\"v1\"); }").await.unwrap();

    // 3. Execute command inside the sandbox
    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "execution test".to_string()])
    } else {
        ("echo", vec!["execution test".to_string()])
    };

    let output = session.exec(cmd, &args, 5000).await.expect("Failed to exec command");
    assert_eq!(output.exit_code, 0);
    assert!(output.stdout.contains("execution test"));

    // 4. Create snapshot checkpoint
    let cp = session.create_checkpoint("checkpoint-v1").await.expect("Failed to create checkpoint");
    assert_eq!(cp.name, "checkpoint-v1");
    assert!(!cp.id.is_empty());

    // 5. Mutate workspace (modify existing file + create new file)
    tokio::fs::write(&file1_path, b"fn main() { println!(\"v2 modified\"); }").await.unwrap();
    let file2_path = tmp.path().join("dirty.txt");
    tokio::fs::write(&file2_path, b"dirty data").await.unwrap();

    assert_eq!(tokio::fs::read_to_string(&file1_path).await.unwrap(), "fn main() { println!(\"v2 modified\"); }");
    assert!(file2_path.exists());

    // 6. Rollback to checkpoint
    session.rollback(&cp.id).await.expect("Failed to rollback");

    // Verify workspace state is restored
    let restored_code = tokio::fs::read_to_string(&file1_path).await.unwrap();
    assert_eq!(restored_code, "fn main() { println!(\"v1\"); }");
    assert!(!file2_path.exists(), "Mutated file should be removed after rollback");

    // 7. Release sandbox back to pool
    pool.release_sandbox(session.id()).await.expect("Failed to release sandbox");
    assert_eq!(pool.warm_count().await, 3);
}

#[tokio::test]
async fn test_full_sandbox_lifecycle_mcp_rpc() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let workspace_path = tmp.path().to_str().unwrap().to_string();

    let server = AgentKernelMcpServer::with_local_pool(3);

    // MCP initialize
    let init_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(1)),
        "initialize",
        Some(json!({ "protocolVersion": "2024-11-05" })),
    )).await;
    assert_eq!(init_resp.result.unwrap()["serverInfo"]["name"], "agentkernel");

    // MCP tools/list
    let list_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(2)),
        "tools/list",
        None,
    )).await;
    let tools = list_resp.result.unwrap()["tools"].as_array().unwrap().len();
    assert_eq!(tools, 7);

    // 1. acquire sandbox
    let acq_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": { "workspace_path": workspace_path }
        })),
    )).await;
    let acq_txt = acq_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let acq_val: serde_json::Value = serde_json::from_str(&acq_txt).unwrap();
    let session_id = acq_val["session_id"].as_str().unwrap().to_string();

    // 2. write baseline file
    server.handle_request(JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "app.py",
                "content": "print('hello v1')"
            }
        })),
    )).await;

    // 3. create checkpoint
    let cp_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": session_id,
                "name": "cp1"
            }
        })),
    )).await;
    let cp_txt = cp_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let cp_val: serde_json::Value = serde_json::from_str(&cp_txt).unwrap();
    let cp_id = cp_val["checkpoint_id"].as_str().unwrap().to_string();

    // 4. mutate file
    server.handle_request(JsonRpcRequest::new(
        Some(json!(6)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "app.py",
                "content": "print('broken mutation')"
            }
        })),
    )).await;

    // verify modified
    let read_mod = server.handle_request(JsonRpcRequest::new(
        Some(json!(7)),
        "tools/call",
        Some(json!({
            "name": "sandbox_read_file",
            "arguments": { "session_id": session_id, "path": "app.py" }
        })),
    )).await;
    assert_eq!(read_mod.result.unwrap()["content"][0]["text"].as_str().unwrap(), "print('broken mutation')");

    // 5. rollback
    server.handle_request(JsonRpcRequest::new(
        Some(json!(8)),
        "tools/call",
        Some(json!({
            "name": "sandbox_rollback",
            "arguments": { "session_id": session_id, "checkpoint_id": cp_id }
        })),
    )).await;

    // verify restored
    let read_restored = server.handle_request(JsonRpcRequest::new(
        Some(json!(9)),
        "tools/call",
        Some(json!({
            "name": "sandbox_read_file",
            "arguments": { "session_id": session_id, "path": "app.py" }
        })),
    )).await;
    assert_eq!(read_restored.result.unwrap()["content"][0]["text"].as_str().unwrap(), "print('hello v1')");

    // 6. release
    let rel_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(10)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": { "session_id": session_id }
        })),
    )).await;
    assert_eq!(rel_resp.result.unwrap()["isError"], json!(null));
}
