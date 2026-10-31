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
        tenant_id: None,
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
    assert_eq!(tools, 10);

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

#[tokio::test]
async fn test_mcp_diff_and_rollback_integration() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let workspace_path = tmp.path().to_str().unwrap().to_string();

    let server = AgentKernelMcpServer::with_local_pool(2);

    // 1. Acquire sandbox
    let acq_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": { "workspace_path": workspace_path }
        })),
    )).await;
    let acq_txt = acq_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let acq_val: serde_json::Value = serde_json::from_str(&acq_txt).unwrap();
    let session_id = acq_val["session_id"].as_str().unwrap().to_string();

    // 2. Create initial files
    server.handle_request(JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "app.py",
                "content": "def run():\n    print('base code')\n"
            }
        })),
    )).await;

    server.handle_request(JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "config.json",
                "content": "{\"env\":\"base\"}\n"
            }
        })),
    )).await;

    // 3. Create snapshot checkpoint
    let cp_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": session_id,
                "name": "cp-base"
            }
        })),
    )).await;
    let cp_txt = cp_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let cp_val: serde_json::Value = serde_json::from_str(&cp_txt).unwrap();
    let cp_id = cp_val["checkpoint_id"].as_str().unwrap().to_string();

    // 4. Mutate workspace (modify app.py, add patch.py)
    server.handle_request(JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "app.py",
                "content": "def run():\n    print('modified v2 code')\n"
            }
        })),
    )).await;

    server.handle_request(JsonRpcRequest::new(
        Some(json!(6)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "patch.py",
                "content": "# newly added patch\n"
            }
        })),
    )).await;

    // 5. Query sandbox_diff via MCP RPC
    let diff_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(7)),
        "tools/call",
        Some(json!({
            "name": "sandbox_diff",
            "arguments": {
                "session_id": session_id,
                "from_checkpoint": cp_id
            }
        })),
    )).await;
    let diff_txt = diff_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let diff_val: serde_json::Value = serde_json::from_str(&diff_txt).unwrap();

    let files = diff_val["files"].as_array().expect("files array in diff");
    assert_eq!(files.len(), 2, "Expected exactly 2 changed files");
    let file_names: Vec<&str> = files.iter().filter_map(|v| v.as_str()).collect();
    assert!(file_names.contains(&"app.py"));
    assert!(file_names.contains(&"patch.py"));

    let diff_str = diff_val["diff"].as_str().unwrap();
    assert!(diff_str.contains("--- a/app.py"));
    assert!(diff_str.contains("+++ b/app.py"));
    assert!(diff_str.contains("-    print('base code')"));
    assert!(diff_str.contains("+    print('modified v2 code')"));
    assert!(diff_str.contains("+++ b/patch.py"));

    // 6. Rollback to checkpoint
    let rb_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(8)),
        "tools/call",
        Some(json!({
            "name": "sandbox_rollback",
            "arguments": {
                "session_id": session_id,
                "checkpoint_id": cp_id
            }
        })),
    )).await;
    assert_eq!(rb_resp.result.unwrap()["isError"], json!(null));

    // 7. Verify diff after rollback is completely clean
    let diff_clean_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(9)),
        "tools/call",
        Some(json!({
            "name": "sandbox_diff",
            "arguments": {
                "session_id": session_id,
                "from_checkpoint": cp_id
            }
        })),
    )).await;
    let diff_clean_txt = diff_clean_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let diff_clean_val: serde_json::Value = serde_json::from_str(&diff_clean_txt).unwrap();
    assert_eq!(diff_clean_val["files"].as_array().unwrap().len(), 0);

    // 8. Release
    server.handle_request(JsonRpcRequest::new(
        Some(json!(10)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": { "session_id": session_id }
        })),
    )).await;
}

#[tokio::test]
async fn test_mcp_list_checkpoints_and_metrics_integration() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let workspace_path = tmp.path().to_str().unwrap().to_string();

    let server = AgentKernelMcpServer::with_local_pool(2);

    // 1. Acquire
    let acq_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": { "workspace_path": workspace_path }
        })),
    )).await;
    let acq_txt = acq_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let acq_val: serde_json::Value = serde_json::from_str(&acq_txt).unwrap();
    let session_id = acq_val["session_id"].as_str().unwrap().to_string();

    // 2. Write file & create checkpoint 1
    server.handle_request(JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "step1.txt",
                "content": "step 1 content\n"
            }
        })),
    )).await;

    let cp1_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": session_id,
                "name": "snap-1"
            }
        })),
    )).await;
    let cp1_txt = cp1_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let cp1_val: serde_json::Value = serde_json::from_str(&cp1_txt).unwrap();
    let cp1_id = cp1_val["checkpoint_id"].as_str().unwrap().to_string();

    // 3. Exec command inside sandbox to accumulate CPU time
    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "metrics_test".to_string()])
    } else {
        ("echo", vec!["metrics_test".to_string()])
    };

    server.handle_request(JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_exec",
            "arguments": {
                "session_id": session_id,
                "cmd": cmd,
                "args": args
            }
        })),
    )).await;

    // 4. Create checkpoint 2
    server.handle_request(JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_write_patch",
            "arguments": {
                "session_id": session_id,
                "path": "step2.txt",
                "content": "step 2 content\n"
            }
        })),
    )).await;

    let cp2_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(6)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": session_id,
                "name": "snap-2"
            }
        })),
    )).await;
    let cp2_txt = cp2_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let cp2_val: serde_json::Value = serde_json::from_str(&cp2_txt).unwrap();
    let cp2_id = cp2_val["checkpoint_id"].as_str().unwrap().to_string();

    // 5. Query sandbox_list_checkpoints
    let list_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(7)),
        "tools/call",
        Some(json!({
            "name": "sandbox_list_checkpoints",
            "arguments": { "session_id": session_id }
        })),
    )).await;
    let list_txt = list_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let list_val: serde_json::Value = serde_json::from_str(&list_txt).unwrap();
    let checkpoints = list_val.as_array().expect("checkpoints array");
    assert_eq!(checkpoints.len(), 2, "Expected 2 checkpoints");

    let ids: Vec<&str> = checkpoints.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&cp1_id.as_str()));
    assert!(ids.contains(&cp2_id.as_str()));

    for cp in checkpoints {
        assert!(cp["size_bytes"].as_u64().unwrap() > 0, "Checkpoint size must be positive");
        assert!(!cp["name"].as_str().unwrap().is_empty());
        assert!(!cp["created_at"].as_str().unwrap().is_empty());
    }

    // 6. Query sandbox_metrics
    let met_resp = server.handle_request(JsonRpcRequest::new(
        Some(json!(8)),
        "tools/call",
        Some(json!({
            "name": "sandbox_metrics",
            "arguments": { "session_id": session_id }
        })),
    )).await;
    let met_txt = met_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let met_val: serde_json::Value = serde_json::from_str(&met_txt).unwrap();

    assert_eq!(met_val["session_id"], session_id);
    assert_eq!(met_val["status"], "leased");
    assert!(met_val["ram_rss_bytes"].as_u64().unwrap() > 0);
    assert!(met_val["disk_layer_bytes"].as_u64().unwrap() > 0);

    // 7. Release
    server.handle_request(JsonRpcRequest::new(
        Some(json!(9)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": { "session_id": session_id }
        })),
    )).await;
}
