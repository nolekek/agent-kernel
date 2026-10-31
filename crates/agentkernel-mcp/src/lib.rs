//! AgentKernel MCP: Model Context Protocol Server (JSON-RPC 2.0).
//!
//! Provides a compliant JSON-RPC 2.0 / MCP 2024-11-05 server over stdio and HTTP/SSE transports,
//! exposing isolated micro-sandbox primitives for autonomous AI coding agents.

pub mod diff;
pub mod local_pool;
pub mod metrics;
pub mod protocol;
pub mod server;
pub mod tools;

pub use diff::{compute_directory_diff, DirectoryDiff};
pub use local_pool::{LocalPoolManager, LocalSandboxSession};
pub use metrics::{compute_dir_size, get_process_rss_bytes, SandboxMetrics};
pub use protocol::{
    CallToolResult, InitializeResult, JsonRpcError, JsonRpcRequest, JsonRpcResponse, ServerCapabilities,
    ServerInfo, Tool, ToolContent, ToolsCapability,
};
pub use server::{ActiveSessionRecord, AgentKernelMcpServer, McpError, McpServer};
pub use tools::{mcp_tools_list, resolve_safe_path};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_initialize_protocol() {
        let server = AgentKernelMcpServer::with_local_pool(2);
        let req = JsonRpcRequest::new(
            Some(json!(1)),
            "initialize",
            Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "claude-code", "version": "1.0.0" }
            })),
        );

        let resp = server.handle_request(req).await;
        assert_eq!(resp.id, Some(json!(1)));
        assert!(resp.error.is_none());

        let result = resp.result.expect("Expected result payload");
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "agentkernel");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn test_tools_list() {
        let server = AgentKernelMcpServer::with_local_pool(2);
        let req = JsonRpcRequest::new(Some(json!("req-2")), "tools/list", None);

        let resp = server.handle_request(req).await;
        assert_eq!(resp.id, Some(json!("req-2")));

        let result = resp.result.expect("Expected tools list");
        let tools = result["tools"].as_array().expect("Expected tools array");
        assert_eq!(tools.len(), 10);

        let tool_names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().expect("tool name"))
            .collect();

        assert!(tool_names.contains(&"sandbox_acquire"));
        assert!(tool_names.contains(&"sandbox_exec"));
        assert!(tool_names.contains(&"sandbox_read_file"));
        assert!(tool_names.contains(&"sandbox_write_patch"));
        assert!(tool_names.contains(&"sandbox_create_checkpoint"));
        assert!(tool_names.contains(&"sandbox_rollback"));
        assert!(tool_names.contains(&"sandbox_release"));
        assert!(tool_names.contains(&"sandbox_diff"));
        assert!(tool_names.contains(&"sandbox_list_checkpoints"));
        assert!(tool_names.contains(&"sandbox_metrics"));
    }

    #[tokio::test]
    async fn test_sandbox_tools_lifecycle() {
        let tmp = tempdir().expect("Failed to create tempdir");
        let workspace_path = tmp.path().to_str().unwrap().to_string();

        let server = AgentKernelMcpServer::with_local_pool(2);

        // 1. sandbox_acquire
        let req_acquire = JsonRpcRequest::new(
            Some(json!(1)),
            "tools/call",
            Some(json!({
                "name": "sandbox_acquire",
                "arguments": {
                    "workspace_path": workspace_path
                }
            })),
        );
        let resp_acquire = server.handle_request(req_acquire).await;
        let res_val = resp_acquire.result.expect("Acquire result");
        assert_eq!(res_val["isError"], json!(null));
        let content_text = res_val["content"][0]["text"].as_str().unwrap();
        let acquire_data: serde_json::Value = serde_json::from_str(content_text).unwrap();
        let session_id = acquire_data["session_id"].as_str().unwrap().to_string();
        assert!(!session_id.is_empty());
        assert_eq!(acquire_data["status"], "leased");

        // 2. sandbox_write_patch
        let req_write = JsonRpcRequest::new(
            Some(json!(2)),
            "tools/call",
            Some(json!({
                "name": "sandbox_write_patch",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt",
                    "content": "Hello AgentKernel!\nLine 2\nLine 3"
                }
            })),
        );
        let resp_write = server.handle_request(req_write).await;
        let res_write = resp_write.result.expect("Write result");
        assert_eq!(res_write["isError"], json!(null));

        // 3. sandbox_read_file
        let req_read = JsonRpcRequest::new(
            Some(json!(3)),
            "tools/call",
            Some(json!({
                "name": "sandbox_read_file",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt"
                }
            })),
        );
        let resp_read = server.handle_request(req_read).await;
        let res_read = resp_read.result.expect("Read result");
        let read_text = res_read["content"][0]["text"].as_str().unwrap();
        assert_eq!(read_text, "Hello AgentKernel!\nLine 2\nLine 3");

        // 3b. sandbox_read_file with offset and limit
        let req_read_slice = JsonRpcRequest::new(
            Some(json!(4)),
            "tools/call",
            Some(json!({
                "name": "sandbox_read_file",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt",
                    "offset": 2,
                    "limit": 1
                }
            })),
        );
        let resp_read_slice = server.handle_request(req_read_slice).await;
        let slice_text = resp_read_slice.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        assert_eq!(slice_text, "Line 2");

        // 4. sandbox_create_checkpoint
        let req_cp = JsonRpcRequest::new(
            Some(json!(5)),
            "tools/call",
            Some(json!({
                "name": "sandbox_create_checkpoint",
                "arguments": {
                    "session_id": session_id,
                    "name": "snap-1"
                }
            })),
        );
        let resp_cp = server.handle_request(req_cp).await;
        let res_cp = resp_cp.result.expect("Checkpoint result");
        let cp_text = res_cp["content"][0]["text"].as_str().unwrap();
        let cp_data: serde_json::Value = serde_json::from_str(cp_text).unwrap();
        let checkpoint_id = cp_data["checkpoint_id"].as_str().unwrap().to_string();
        assert!(!checkpoint_id.is_empty());

        // 5. Modify file
        let req_mod = JsonRpcRequest::new(
            Some(json!(6)),
            "tools/call",
            Some(json!({
                "name": "sandbox_write_patch",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt",
                    "content": "Modified content!"
                }
            })),
        );
        server.handle_request(req_mod).await;

        // Verify modified
        let req_read_mod = JsonRpcRequest::new(
            Some(json!(7)),
            "tools/call",
            Some(json!({
                "name": "sandbox_read_file",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt"
                }
            })),
        );
        let resp_mod = server.handle_request(req_read_mod).await;
        assert_eq!(resp_mod.result.unwrap()["content"][0]["text"].as_str().unwrap(), "Modified content!");

        // 6. sandbox_rollback
        let req_rb = JsonRpcRequest::new(
            Some(json!(8)),
            "tools/call",
            Some(json!({
                "name": "sandbox_rollback",
                "arguments": {
                    "session_id": session_id,
                    "checkpoint_id": checkpoint_id
                }
            })),
        );
        let resp_rb = server.handle_request(req_rb).await;
        assert_eq!(resp_rb.result.expect("Rollback result")["isError"], json!(null));

        // Verify restored content
        let req_read_restored = JsonRpcRequest::new(
            Some(json!(9)),
            "tools/call",
            Some(json!({
                "name": "sandbox_read_file",
                "arguments": {
                    "session_id": session_id,
                    "path": "hello.txt"
                }
            })),
        );
        let resp_restored = server.handle_request(req_read_restored).await;
        assert_eq!(resp_restored.result.unwrap()["content"][0]["text"].as_str().unwrap(), "Hello AgentKernel!\nLine 2\nLine 3");

        // 6b. sandbox_exec
        let (cmd, args) = if cfg!(windows) {
            ("cmd", vec!["/C".to_string(), "echo".to_string(), "sandbox exec ok".to_string()])
        } else {
            ("echo", vec!["sandbox exec ok".to_string()])
        };

        let req_exec = JsonRpcRequest::new(
            Some(json!(10)),
            "tools/call",
            Some(json!({
                "name": "sandbox_exec",
                "arguments": {
                    "session_id": session_id,
                    "cmd": cmd,
                    "args": args
                }
            })),
        );
        let resp_exec = server.handle_request(req_exec).await;
        let res_exec = resp_exec.result.expect("Exec result");
        assert_eq!(res_exec["isError"], json!(null));
        let exec_text = res_exec["content"][0]["text"].as_str().unwrap();
        assert!(exec_text.contains("sandbox exec ok"));

        // 7. sandbox_release
        let req_rel = JsonRpcRequest::new(
            Some(json!(11)),
            "tools/call",
            Some(json!({
                "name": "sandbox_release",
                "arguments": {
                    "session_id": session_id
                }
            })),
        );
        let resp_rel = server.handle_request(req_rel).await;
        assert_eq!(resp_rel.result.expect("Release result")["isError"], json!(null));
    }

    #[tokio::test]
    async fn test_path_traversal_blocked() {
        let tmp = tempdir().expect("Failed to create tempdir");
        let workspace_path = tmp.path().to_str().unwrap().to_string();

        let server = AgentKernelMcpServer::with_local_pool(1);

        let req_acquire = JsonRpcRequest::new(
            Some(json!(1)),
            "tools/call",
            Some(json!({
                "name": "sandbox_acquire",
                "arguments": { "workspace_path": workspace_path }
            })),
        );
        let resp = server.handle_request(req_acquire).await;
        let session_id = serde_json::from_str::<serde_json::Value>(
            resp.result.unwrap()["content"][0]["text"].as_str().unwrap(),
        )
        .unwrap()["session_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Attempt directory traversal read
        let req_traversal = JsonRpcRequest::new(
            Some(json!(2)),
            "tools/call",
            Some(json!({
                "name": "sandbox_read_file",
                "arguments": {
                    "session_id": session_id,
                    "path": "../../Windows/System32/drivers/etc/hosts"
                }
            })),
        );
        let resp_traversal = server.handle_request(req_traversal).await;
        let res = resp_traversal.result.unwrap();
        assert_eq!(res["isError"], json!(true));
        assert!(res["content"][0]["text"].as_str().unwrap().contains("traversal"));
    }

    #[tokio::test]
    async fn test_stream_stdio_transport() {
        let server = Arc::new(AgentKernelMcpServer::with_local_pool(1));

        // Use tokio duplex to simulate bidirectional stdin/stdout stream
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (server_reader, server_writer) = tokio::io::split(server_io);
        let server_buf_reader = tokio::io::BufReader::new(server_reader);

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                server.run_stream(server_buf_reader, server_writer).await
            })
        };

        let (client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut client_buf_reader = tokio::io::BufReader::new(client_reader);

        // Send JSON-RPC request line
        let ping_req = r#"{"jsonrpc":"2.0","id":42,"method":"ping"}"#;
        client_writer.write_all(ping_req.as_bytes()).await.unwrap();
        client_writer.write_all(b"\n").await.unwrap();
        client_writer.flush().await.unwrap();

        // Read response line
        let mut resp_line = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut client_buf_reader, &mut resp_line)
            .await
            .unwrap();

        let resp: JsonRpcResponse = serde_json::from_str(resp_line.trim()).unwrap();
        assert_eq!(resp.id, Some(json!(42)));
        assert_eq!(resp.result, Some(json!({})));

        server_task.abort();
    }

    #[tokio::test]
    async fn test_mcp_diff_checkpoint_and_metrics() {
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

        // 2. Write initial file
        server.handle_request(JsonRpcRequest::new(
            Some(json!(2)),
            "tools/call",
            Some(json!({
                "name": "sandbox_write_patch",
                "arguments": {
                    "session_id": session_id,
                    "path": "test.txt",
                    "content": "line 1\nline 2\n"
                }
            })),
        )).await;

        // 3. Create checkpoint
        let cp_resp = server.handle_request(JsonRpcRequest::new(
            Some(json!(3)),
            "tools/call",
            Some(json!({
                "name": "sandbox_create_checkpoint",
                "arguments": {
                    "session_id": session_id,
                    "name": "v1.0"
                }
            })),
        )).await;
        let cp_txt = cp_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        let cp_val: serde_json::Value = serde_json::from_str(&cp_txt).unwrap();
        let cp_id = cp_val["checkpoint_id"].as_str().unwrap().to_string();

        // 4. List checkpoints
        let list_resp = server.handle_request(JsonRpcRequest::new(
            Some(json!(4)),
            "tools/call",
            Some(json!({
                "name": "sandbox_list_checkpoints",
                "arguments": { "session_id": session_id }
            })),
        )).await;
        let list_txt = list_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        let list_val: serde_json::Value = serde_json::from_str(&list_txt).unwrap();
        let cps = list_val.as_array().unwrap();
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0]["name"], "v1.0");
        assert!(cps[0]["size_bytes"].as_u64().unwrap() > 0);

        // 5. Query metrics
        let met_resp = server.handle_request(JsonRpcRequest::new(
            Some(json!(5)),
            "tools/call",
            Some(json!({
                "name": "sandbox_metrics",
                "arguments": { "session_id": session_id }
            })),
        )).await;
        let met_txt = met_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        let met_val: serde_json::Value = serde_json::from_str(&met_txt).unwrap();
        assert_eq!(met_val["status"], "leased");
        assert!(met_val["ram_rss_bytes"].as_u64().unwrap() > 0);

        // 6. Mutate file and add a second file
        server.handle_request(JsonRpcRequest::new(
            Some(json!(6)),
            "tools/call",
            Some(json!({
                "name": "sandbox_write_patch",
                "arguments": {
                    "session_id": session_id,
                    "path": "test.txt",
                    "content": "line 1\nline 2 modified\n"
                }
            })),
        )).await;

        server.handle_request(JsonRpcRequest::new(
            Some(json!(7)),
            "tools/call",
            Some(json!({
                "name": "sandbox_write_patch",
                "arguments": {
                    "session_id": session_id,
                    "path": "new.txt",
                    "content": "brand new file\n"
                }
            })),
        )).await;

        // 7. Check diff against cp1
        let diff_resp = server.handle_request(JsonRpcRequest::new(
            Some(json!(8)),
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
        let files = diff_val["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        let diff_str = diff_val["diff"].as_str().unwrap();
        assert!(diff_str.contains("--- a/test.txt"));
        assert!(diff_str.contains("+line 2 modified"));
        assert!(diff_str.contains("+++ b/new.txt"));

        // 8. Rollback
        server.handle_request(JsonRpcRequest::new(
            Some(json!(9)),
            "tools/call",
            Some(json!({
                "name": "sandbox_rollback",
                "arguments": {
                    "session_id": session_id,
                    "checkpoint_id": cp_id
                }
            })),
        )).await;

        // 9. Diff after rollback should be clean
        let diff2_resp = server.handle_request(JsonRpcRequest::new(
            Some(json!(10)),
            "tools/call",
            Some(json!({
                "name": "sandbox_diff",
                "arguments": {
                    "session_id": session_id,
                    "from_checkpoint": cp_id
                }
            })),
        )).await;
        let diff2_txt = diff2_resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        let diff2_val: serde_json::Value = serde_json::from_str(&diff2_txt).unwrap();
        assert_eq!(diff2_val["files"].as_array().unwrap().len(), 0);

        // 10. Release
        server.handle_request(JsonRpcRequest::new(
            Some(json!(11)),
            "tools/call",
            Some(json!({
                "name": "sandbox_release",
                "arguments": { "session_id": session_id }
            })),
        )).await;
    }

    #[tokio::test]
    async fn test_http_sse_streaming() {
        let tmp = tempdir().expect("Failed to create tempdir");
        let workspace_path = tmp.path().to_str().unwrap().to_string();

        let server = Arc::new(AgentKernelMcpServer::with_local_pool(1));

        // Start HTTP server on local random free port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server_addr = format!("127.0.0.1:{port}");
        let server_clone = server.clone();
        let addr_clone = server_addr.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_clone.run_http_sse(&addr_clone).await;
        });

        // Give server time to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Acquire sandbox
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

        // Connect SSE stream
        let mut stream_sock = tokio::net::TcpStream::connect(&server_addr).await.unwrap();
        let req = format!("GET /sandbox/{session_id}/stream HTTP/1.1\r\nHost: {server_addr}\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut stream_sock, req.as_bytes()).await.unwrap();

        let mut buf_reader = tokio::io::BufReader::new(stream_sock);
        let mut line = String::new();

        // Read headers until \r\n\r\n
        loop {
            line.clear();
            let n = tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await.unwrap();
            assert!(n > 0);
            if line.trim().is_empty() {
                break;
            }
        }

        // Read event: connected
        line.clear();
        tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line).await.unwrap();
        assert!(line.contains("event: connected"));

        // Trigger command execution in background
        let server_clone2 = server.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let (cmd, args) = if cfg!(windows) {
                ("cmd", vec!["/C".to_string(), "echo".to_string(), "streaming-test-output".to_string()])
            } else {
                ("echo", vec!["streaming-test-output".to_string()])
            };
            let _ = server_clone2.handle_request(JsonRpcRequest::new(
                Some(json!(2)),
                "tools/call",
                Some(json!({
                    "name": "sandbox_exec",
                    "arguments": {
                        "session_id": session_id_clone,
                        "cmd": cmd,
                        "args": args
                    }
                })),
            )).await;
        });

        // Read SSE stream lines and look for "streaming-test-output"
        let mut found_output = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            line.clear();
            if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(500), tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut line)).await {
                if n == 0 { break; }
                if line.contains("streaming-test-output") {
                    found_output = true;
                    break;
                }
            }
        }

        assert!(found_output, "SSE stream must receive command output in real time");
        server_task.abort();
    }
}
