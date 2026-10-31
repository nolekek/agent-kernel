//! Prometheus Metrics End-to-End Validation Test Suite for AgentKernel.
//! Verifies:
//! 1. Metrics Lifecycle: Cold boot, Command execution, Checkpoint creation, Rollback, Release.
//! 2. Metrics Incrementation: agentkernel_commands_total strictly increments on each command.
//! 3. Standard Prometheus Format: Presence of # HELP, # TYPE, valid gauge/counter/histogram syntax.
//! 4. HTTP /metrics Endpoint: Content-Type: text/plain; version=0.0.4, real-time scraping.

use agentkernel_core::metrics::MetricsRegistry;
use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::SandboxConfig;
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::protocol::JsonRpcRequest;
use agentkernel_mcp::server::AgentKernelMcpServer;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper to allocate an ephemeral TCP port for testing HTTP servers.
async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral listener");
    let port = listener.local_addr().expect("Failed to get local addr").port();
    drop(listener);
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

// ============================================================================
// Test 1: Full Lifecycle & Prometheus Rendering (Direct Core Engine)
// ============================================================================

#[tokio::test]
async fn test_prometheus_metrics_lifecycle_direct() {
    let tmp = tempdir().expect("tempdir");
    let workspace = tmp.path().to_str().unwrap().to_string();

    let metrics = Arc::new(MetricsRegistry::new());
    let pool = Arc::new(LocalPoolManager::new(0));

    // Baseline checks before leasing
    assert_eq!(metrics.cold_boot_total.get(), 0);
    assert_eq!(metrics.commands_total.get(), 0);
    assert_eq!(metrics.sandboxes_leased.get(), 0);

    // 1. Cold boot sandbox acquisition
    let cfg = SandboxConfig {
        session_id: "sb-metrics-test-1".to_string(),
        tenant_id: None,
        workspace_path: workspace.clone(),
        base_rootfs: None,
        env_vars: vec![],
        timeout_seconds: 60,
    };

    let session = pool
        .acquire_sandbox(cfg)
        .await
        .expect("Acquire sandbox from cold pool");

    metrics.cold_boot_total.inc();
    metrics.sandboxes_leased.set(pool.leased_count().await as i64);

    assert_eq!(
        metrics.cold_boot_total.get(),
        1,
        "Cold boot total counter must be 1"
    );
    assert_eq!(
        metrics.sandboxes_leased.get(),
        1,
        "Sandboxes leased gauge must be 1"
    );

    // Initial state file
    let file1 = tmp.path().join("initial.txt");
    tokio::fs::write(&file1, b"baseline state").await.unwrap();

    // 2. Command execution 1: verify commands_total increments
    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "metric_run_1".to_string()])
    } else {
        ("echo", vec!["metric_run_1".to_string()])
    };

    let out1 = session.exec(cmd, &args, 5000).await.unwrap();
    assert_eq!(out1.exit_code, 0);
    metrics.commands_total.inc();
    assert_eq!(
        metrics.commands_total.get(),
        1,
        "Commands total must be 1 after first exec"
    );

    // Command execution 2: verify second increment
    let out2 = session.exec(cmd, &args, 5000).await.unwrap();
    assert_eq!(out2.exit_code, 0);
    metrics.commands_total.inc();
    assert_eq!(
        metrics.commands_total.get(),
        2,
        "Commands total must be 2 after second exec"
    );

    // 3. Checkpoint snapshot creation
    let timer_cp = metrics.checkpoint_duration_seconds.start_timer();
    let cp = session
        .create_checkpoint("cp-metrics-snapshot")
        .await
        .expect("create checkpoint");
    drop(timer_cp);

    assert_eq!(
        metrics.checkpoint_duration_seconds.get_count(),
        1,
        "Checkpoint histogram must have 1 observation"
    );

    // 4. Mutate workspace and Rollback
    tokio::fs::write(&file1, b"corrupted state").await.unwrap();
    let timer_rb = metrics.rollback_duration_seconds.start_timer();
    session.rollback(&cp.id).await.expect("rollback");
    drop(timer_rb);

    assert_eq!(
        metrics.rollback_duration_seconds.get_count(),
        1,
        "Rollback histogram must have 1 observation"
    );
    let restored = tokio::fs::read_to_string(&file1).await.unwrap();
    assert_eq!(restored, "baseline state");

    // 5. Release sandbox
    pool.release_sandbox(session.id()).await.unwrap();
    metrics.sandboxes_leased.set(pool.leased_count().await as i64);
    assert_eq!(
        metrics.sandboxes_leased.get(),
        0,
        "Sandboxes leased gauge must return to 0 after release"
    );

    // 6. Prometheus text exposition format validation
    let rendered = metrics.render_prometheus_metrics();

    // Verify presence of all required HELP and TYPE declarations
    assert!(
        rendered.contains("# HELP agentkernel_sandboxes_leased Current number of actively leased sandboxes"),
        "Missing HELP for agentkernel_sandboxes_leased"
    );
    assert!(
        rendered.contains("# TYPE agentkernel_sandboxes_leased gauge"),
        "Missing TYPE for agentkernel_sandboxes_leased"
    );
    assert!(
        rendered.contains("agentkernel_sandboxes_leased 0"),
        "Invalid value for agentkernel_sandboxes_leased"
    );

    assert!(
        rendered.contains("# HELP agentkernel_cold_boot_total Total count of cold sandbox boot operations"),
        "Missing HELP for agentkernel_cold_boot_total"
    );
    assert!(
        rendered.contains("# TYPE agentkernel_cold_boot_total counter"),
        "Missing TYPE for agentkernel_cold_boot_total"
    );
    assert!(
        rendered.contains("agentkernel_cold_boot_total 1"),
        "Invalid value for agentkernel_cold_boot_total"
    );

    assert!(
        rendered.contains("# HELP agentkernel_commands_total Total count of commands executed inside sandboxes"),
        "Missing HELP for agentkernel_commands_total"
    );
    assert!(
        rendered.contains("# TYPE agentkernel_commands_total counter"),
        "Missing TYPE for agentkernel_commands_total"
    );
    assert!(
        rendered.contains("agentkernel_commands_total 2"),
        "Commands total must be 2 in rendered Prometheus metrics"
    );

    // Check histogram components
    assert!(
        rendered.contains("# HELP agentkernel_checkpoint_duration_seconds"),
        "Missing checkpoint duration histogram"
    );
    assert!(
        rendered.contains("# TYPE agentkernel_checkpoint_duration_seconds histogram"),
        "Missing checkpoint histogram type"
    );
    assert!(
        rendered.contains("agentkernel_checkpoint_duration_seconds_count 1"),
        "Histogram count must be 1"
    );
    assert!(
        rendered.contains("agentkernel_checkpoint_duration_seconds_bucket{le=\"+Inf\"} 1"),
        "Histogram +Inf bucket must be 1"
    );
}

// ============================================================================
// Test 2: Prometheus Metrics Increment via MCP Server API
// ============================================================================

#[tokio::test]
async fn test_prometheus_metrics_mcp_rpc_e2e() {
    let tmp = tempdir().expect("tempdir");
    let ws = tmp.path().to_str().unwrap().to_string();

    let pool = Arc::new(LocalPoolManager::new(2));
    let server = AgentKernelMcpServer::new(pool);

    // Baseline metrics
    let rendered_0 = server.render_prometheus_metrics();
    assert!(rendered_0.contains("agentkernel_commands_total 0"));

    // 1. Acquire sandbox
    let req_acq = JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": { "workspace_path": ws }
        })),
    );
    let resp_acq = server.handle_request(req_acq).await;
    let res_acq = resp_acq.result.expect("Acquire result");
    let txt_acq = res_acq["content"][0]["text"].as_str().unwrap();
    let val_acq: serde_json::Value = serde_json::from_str(txt_acq).unwrap();
    let session_id = val_acq["session_id"].as_str().unwrap().to_string();

    // 2. Execute command 1 via MCP
    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "mcp-cmd-1".to_string()])
    } else {
        ("echo", vec!["mcp-cmd-1".to_string()])
    };

    let req_exec1 = JsonRpcRequest::new(
        Some(json!(2)),
        "tools/call",
        Some(json!({
            "name": "sandbox_exec",
            "arguments": {
                "session_id": session_id.clone(),
                "cmd": cmd,
                "args": args
            }
        })),
    );
    let resp_exec1 = server.handle_request(req_exec1).await;
    assert_eq!(resp_exec1.result.unwrap()["isError"], json!(null));

    // Verify counter incremented to 1
    let rendered_1 = server.render_prometheus_metrics();
    assert!(
        rendered_1.contains("agentkernel_commands_total 1"),
        "Counter must increment to 1 after 1st command execution: {rendered_1}"
    );

    // 3. Execute command 2 via MCP
    let req_exec2 = JsonRpcRequest::new(
        Some(json!(3)),
        "tools/call",
        Some(json!({
            "name": "sandbox_exec",
            "arguments": {
                "session_id": session_id.clone(),
                "cmd": cmd,
                "args": args
            }
        })),
    );
    let resp_exec2 = server.handle_request(req_exec2).await;
    assert_eq!(resp_exec2.result.unwrap()["isError"], json!(null));

    // Verify counter incremented to 2
    let rendered_2 = server.render_prometheus_metrics();
    assert!(
        rendered_2.contains("agentkernel_commands_total 2"),
        "Counter must increment to 2 after 2nd command execution: {rendered_2}"
    );

    // 4. Create checkpoint
    let req_cp = JsonRpcRequest::new(
        Some(json!(4)),
        "tools/call",
        Some(json!({
            "name": "sandbox_create_checkpoint",
            "arguments": {
                "session_id": session_id.clone(),
                "name": "mcp-snap-1"
            }
        })),
    );
    let resp_cp = server.handle_request(req_cp).await;
    assert_eq!(resp_cp.result.unwrap()["isError"], json!(null));

    let rendered_cp = server.render_prometheus_metrics();
    assert!(
        rendered_cp.contains("agentkernel_checkpoint_duration_seconds_count 1"),
        "Checkpoint histogram must record snapshot creation"
    );

    // 5. Release sandbox
    let req_rel = JsonRpcRequest::new(
        Some(json!(5)),
        "tools/call",
        Some(json!({
            "name": "sandbox_release",
            "arguments": { "session_id": session_id }
        })),
    );
    let resp_rel = server.handle_request(req_rel).await;
    assert_eq!(resp_rel.result.unwrap()["isError"], json!(null));
}

// ============================================================================
// Test 3: Prometheus Metrics HTTP Scraping Endpoint (/metrics)
// ============================================================================

#[tokio::test]
async fn test_prometheus_metrics_http_endpoint_scraping() {
    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{port}");

    let pool = Arc::new(LocalPoolManager::new(2));
    let server = Arc::new(AgentKernelMcpServer::new(pool));

    let server_task = {
        let server_clone = server.clone();
        let addr_clone = addr.clone();
        tokio::spawn(async move {
            let _ = server_clone.run_http_sse(&addr_clone).await;
        })
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Helper to scrape GET /metrics
    async fn fetch_metrics(addr: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("Failed to connect to metrics endpoint");

        let request = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf_reader = tokio::io::BufReader::new(stream);
        let mut status_line = String::new();
        buf_reader.read_line(&mut status_line).await.unwrap();

        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);

        let mut content_type = String::new();
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
                if k.trim().eq_ignore_ascii_case("content-type") {
                    content_type = v.trim().to_string();
                } else if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            buf_reader.read_exact(&mut body).await.unwrap();
        } else {
            let _ = buf_reader.read_to_end(&mut body).await;
        }

        let body_str = String::from_utf8_lossy(&body).to_string();
        (status_code, content_type, body_str)
    }

    // 1. Initial metrics scrape
    let (status, content_type, body) = fetch_metrics(&addr).await;
    assert_eq!(status, 200, "Scraping /metrics must return HTTP 200");
    assert!(
        content_type.contains("text/plain"),
        "Content-Type must be text/plain, got: {content_type}"
    );
    assert!(
        body.contains("# HELP agentkernel_commands_total") && body.contains("# TYPE agentkernel_commands_total counter"),
        "Response must contain Prometheus format declarations"
    );
    assert!(body.contains("agentkernel_commands_total 0"));

    // 2. Perform command execution in background
    let tmp = tempdir().unwrap();
    let ws = tmp.path().to_str().unwrap().to_string();
    let req_acq = JsonRpcRequest::new(
        Some(json!(1)),
        "tools/call",
        Some(json!({
            "name": "sandbox_acquire",
            "arguments": { "workspace_path": ws }
        })),
    );
    let resp_acq = server.handle_request(req_acq).await;
    let txt_acq = resp_acq.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
    let val_acq: serde_json::Value = serde_json::from_str(&txt_acq).unwrap();
    let session_id = val_acq["session_id"].as_str().unwrap().to_string();

    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "http_scrape_test".to_string()])
    } else {
        ("echo", vec!["http_scrape_test".to_string()])
    };

    let req_exec = JsonRpcRequest::new(
        Some(json!(2)),
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
    server.handle_request(req_exec).await;

    // 3. Second metrics scrape: verify increment in HTTP endpoint output
    let (status2, _, body2) = fetch_metrics(&addr).await;
    assert_eq!(status2, 200);
    assert!(
        body2.contains("agentkernel_commands_total 1"),
        "Scraped Prometheus metrics must reflect incremented command counter: {body2}"
    );

    server_task.abort();
}

// ============================================================================
// Test 4: Prometheus Syntax Parser & Compliance Validation
// ============================================================================

#[test]
fn test_prometheus_format_strict_syntax_compliance() {
    let registry = MetricsRegistry::new();

    registry.sandboxes_warm.set(3);
    registry.sandboxes_leased.set(2);
    registry.sandboxes_total.set(5);
    registry.cold_boot_total.inc_by(4);
    registry.warm_boot_total.inc_by(7);
    registry.commands_total.inc_by(15);
    registry.quota_violations_total.inc_by(1);

    registry.cold_boot_duration_seconds.observe(0.012);
    registry.checkpoint_duration_seconds.observe(0.045);
    registry.rollback_duration_seconds.observe(0.008);

    let output = registry.render_prometheus_metrics();

    let mut current_help: Option<String> = None;
    let mut current_type: Option<String> = None;
    let mut validated_metrics = 0;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            current_help = None;
            current_type = None;
            continue;
        }

        if let Some(help_content) = trimmed.strip_prefix("# HELP ") {
            let parts: Vec<&str> = help_content.split_whitespace().collect();
            assert!(
                parts.len() >= 2,
                "# HELP line must include metric name and description: {line}"
            );
            current_help = Some(parts[0].to_string());
        } else if let Some(type_content) = trimmed.strip_prefix("# TYPE ") {
            let parts: Vec<&str> = type_content.split_whitespace().collect();
            assert_eq!(
                parts.len(),
                2,
                "# TYPE line must contain exactly metric name and type: {line}"
            );
            let metric_name = parts[0];
            let metric_type = parts[1];
            assert!(
                ["gauge", "counter", "histogram"].contains(&metric_type),
                "Invalid metric type '{metric_type}' in: {line}"
            );
            assert_eq!(
                current_help.as_deref(),
                Some(metric_name),
                "# TYPE metric name must match preceding # HELP"
            );
            current_type = Some(metric_type.to_string());
        } else {
            // Sample line
            assert!(
                current_type.is_some(),
                "Metric sample must follow # TYPE declaration: {line}"
            );
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            assert_eq!(
                parts.len(),
                2,
                "Metric sample line must be '<name>[{{labels}}] <value>': {line}"
            );
            let val = parts[1].parse::<f64>();
            assert!(
                val.is_ok(),
                "Metric value must be valid float or integer: {line}"
            );
            validated_metrics += 1;
        }
    }

    assert!(
        validated_metrics >= 30,
        "Expected at least 30 valid metric sample lines, validated: {validated_metrics}"
    );
}
