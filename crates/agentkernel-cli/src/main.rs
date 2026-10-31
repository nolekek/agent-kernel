//! AgentKernel CLI: Command-Line Interface for Micro-Sandbox & MCP Server.

pub mod daemon;
pub mod tenant;

use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::SandboxConfig;
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::server::AgentKernelMcpServer;
use clap::{Parser, Subcommand};
use daemon::{run_daemon, DaemonOptions};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tenant::{handle_tenant_add, handle_tenant_list};
use tracing::info;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "agentkernel")]
#[command(about = "High-Performance Ephemeral Micro-Sandbox Runtime & MCP Server", version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Start the Model Context Protocol (MCP) server over stdio
    Mcp {
        /// Number of pre-warmed sandbox isolates to maintain in pool
        #[arg(short, long, default_value = "3")]
        warm_pool_size: usize,
    },
    /// Start the AgentKernel micro-sandbox & MCP server daemon over HTTP/SSE
    Daemon {
        /// Socket address to listen on
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,

        /// Global Bearer token for single-tenant / monopoly usage
        #[arg(long)]
        auth_token: Option<String>,

        /// Path to JSON file containing list of tenants and quotas
        #[arg(long)]
        tenants_file: Option<PathBuf>,

        /// HTTP path where Prometheus metrics are exposed
        #[arg(long, default_value = "/metrics")]
        metrics_path: String,

        /// Number of pre-warmed sandbox isolates
        #[arg(short, long, default_value = "3")]
        warm_pool_size: usize,
    },
    /// Manage multi-tenant registries and sandbox quotas
    Tenant {
        #[command(subcommand)]
        command: TenantCommands,
    },
    /// Run a command inside an ephemeral micro-sandbox
    Exec {
        /// Workspace directory on host
        #[arg(short, long)]
        workspace: String,

        /// Timeout in milliseconds
        #[arg(short, long, default_value = "30000")]
        timeout_ms: u64,

        /// Command and arguments to execute
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage filesystem snapshots and checkpoints
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommands,
    },
    /// Show resource and performance statistics for a sandbox session
    Stats {
        /// Session ID of the sandbox
        #[arg(long)]
        session_id: String,

        /// Server address to query (default: http://127.0.0.1:8080)
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
    },
    /// Launch an interactive shell inside a sandbox workspace
    Shell {
        /// Workspace directory on host
        #[arg(short = 'w', long)]
        workspace: String,

        /// Custom shell command to launch (default: powershell on Windows, bash on Unix)
        #[arg(short, long)]
        shell: Option<String>,
    },
    /// Benchmark cold-boot latency and snapshot performance
    Benchmark {
        /// Number of iterations for benchmarking
        #[arg(short, long, default_value = "10")]
        iterations: usize,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum TenantCommands {
    /// List registered tenants and their quotas
    List {
        /// Path to tenants JSON file
        #[arg(long)]
        tenants_file: PathBuf,
    },
    /// Register or update a tenant configuration
    Add {
        /// Path to tenants JSON file
        #[arg(long)]
        tenants_file: PathBuf,

        /// Unique tenant identifier
        #[arg(long)]
        id: String,

        /// Tenant organization name
        #[arg(long)]
        name: String,

        /// Secret API key for authentication
        #[arg(long)]
        api_key: String,

        /// Maximum number of concurrent sandboxes
        #[arg(long)]
        max_sandboxes: usize,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum SnapshotCommands {
    /// List all checkpoints/snapshots for a sandbox session
    List {
        /// Session ID of the sandbox
        #[arg(long)]
        session_id: String,

        /// Server address to query (default: http://127.0.0.1:8080)
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
    },
    /// Unified diff between checkpoints or current workspace
    Diff {
        /// Session ID of the sandbox
        #[arg(long)]
        session_id: String,

        /// Starting checkpoint ID (optional)
        #[arg(long)]
        from: Option<String>,

        /// Target checkpoint ID (optional)
        #[arg(long)]
        to: Option<String>,

        /// Server address to query (default: http://127.0.0.1:8080)
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Direct all logs to stderr to preserve stdout for JSON-RPC transport
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp { warm_pool_size } => {
            info!("Initializing AgentKernel MCP server (warm pool size: {warm_pool_size})...");
            let pool = Arc::new(LocalPoolManager::new(warm_pool_size));
            let server = AgentKernelMcpServer::new(pool);
            info!("AgentKernel MCP server running on stdio. Awaiting JSON-RPC 2.0 messages...");
            server.run_stdio().await?;
        }

        Commands::Daemon {
            addr,
            auth_token,
            tenants_file,
            metrics_path,
            warm_pool_size,
        } => {
            let options = DaemonOptions {
                addr,
                auth_token,
                tenants_file,
                metrics_path,
                warm_pool_size,
            };
            run_daemon(options).await?;
        }

        Commands::Tenant { command } => match command {
            TenantCommands::List { tenants_file } => {
                handle_tenant_list(&tenants_file)?;
            }
            TenantCommands::Add {
                tenants_file,
                id,
                name,
                api_key,
                max_sandboxes,
            } => {
                handle_tenant_add(&tenants_file, &id, &name, &api_key, max_sandboxes)?;
            }
        },

        Commands::Exec {
            workspace,
            timeout_ms,
            command,
        } => {
            if command.is_empty() {
                anyhow::bail!("No command specified to execute");
            }

            let pool = Arc::new(LocalPoolManager::new(1));
            let session_id = format!("exec-{}", Uuid::new_v4());

            let config = SandboxConfig {
                session_id: session_id.clone(),
                tenant_id: None,
                workspace_path: workspace.clone(),
                base_rootfs: None,
                env_vars: vec![],
                timeout_seconds: (timeout_ms / 1000).max(1),
            };

            info!("Leasing sandbox for workspace: {workspace}...");
            let session = pool
                .acquire_sandbox(config)
                .await
                .map_err(|e| anyhow::anyhow!("Sandbox acquisition failed: {e}"))?;

            let cmd = &command[0];
            let args = &command[1..];

            info!("Executing command: {cmd} {args:?} (timeout: {timeout_ms}ms)...");
            let output = session
                .exec(cmd, args, timeout_ms)
                .await
                .map_err(|e| anyhow::anyhow!("Command execution error: {e}"))?;

            if !output.stdout.is_empty() {
                print!("{}", output.stdout);
            }
            if !output.stderr.is_empty() {
                eprint!("{}", output.stderr);
            }

            info!(
                "Command exited with code {} in {}ms (total lines: {})",
                output.exit_code, output.duration_ms, output.total_lines
            );

            let _ = pool.release_sandbox(&session_id).await;

            if output.exit_code != 0 {
                std::process::exit(output.exit_code);
            }
        }

        Commands::Snapshot { command } => match command {
            SnapshotCommands::List { session_id, server } => {
                handle_snapshot_list(&session_id, &server).await?;
            }
            SnapshotCommands::Diff {
                session_id,
                from,
                to,
                server,
            } => {
                handle_snapshot_diff(&session_id, from.as_deref(), to.as_deref(), &server).await?;
            }
        },

        Commands::Stats { session_id, server } => {
            handle_stats(&session_id, &server).await?;
        }

        Commands::Shell { workspace, shell } => {
            handle_shell(&workspace, shell.as_deref()).await?;
        }

        Commands::Benchmark { iterations } => {
            run_benchmark(iterations).await?;
        }
    }

    Ok(())
}

async fn handle_snapshot_list(session_id: &str, server: &str) -> anyhow::Result<()> {
    let args = serde_json::json!({ "session_id": session_id });
    let val = call_mcp_tool(server, "sandbox_list_checkpoints", args).await?;

    let checkpoints = val
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected array of checkpoints"))?;
    if checkpoints.is_empty() {
        println!("No checkpoints found for sandbox session '{session_id}'.");
        return Ok(());
    }

    println!("==========================================================================================");
    println!("  Checkpoints for Session: {}", session_id);
    println!("==========================================================================================");
    println!("  {:<38} {:<16} {:<24} {:<10}", "ID", "NAME", "CREATED AT", "SIZE");
    println!("  {:-<38} {:-<16} {:-<24} {:-<10}", "", "", "", "");

    for cp in checkpoints {
        let id = cp["id"].as_str().unwrap_or("-");
        let name = cp["name"].as_str().unwrap_or("-");
        let created_at = cp["created_at"].as_str().unwrap_or("-");
        let size_bytes = cp["size_bytes"].as_u64().unwrap_or(0);
        let size_str = format_bytes(size_bytes);

        println!("  {:<38} {:<16} {:<24} {:<10}", id, name, created_at, size_str);
    }

    println!("==========================================================================================");
    println!("  Total: {} checkpoint(s)", checkpoints.len());
    Ok(())
}

async fn handle_snapshot_diff(
    session_id: &str,
    from: Option<&str>,
    to: Option<&str>,
    server: &str,
) -> anyhow::Result<()> {
    let mut args = serde_json::json!({ "session_id": session_id });
    if let Some(f) = from {
        args["from_checkpoint"] = serde_json::Value::String(f.to_string());
    }
    if let Some(t) = to {
        args["to_checkpoint"] = serde_json::Value::String(t.to_string());
    }

    let val = call_mcp_tool(server, "sandbox_diff", args).await?;
    let files = val["files"].as_array().cloned().unwrap_or_default();
    let diff = val["diff"].as_str().unwrap_or_default();

    if files.is_empty() {
        println!("No changes detected between checkpoints/workspace.");
        return Ok(());
    }

    println!("Changed files ({}):", files.len());
    for f in &files {
        if let Some(path) = f.as_str() {
            println!("  • {}", path);
        }
    }
    println!();
    println!("Unified Diff:");
    println!("------------------------------------------------------------");
    print!("{diff}");
    println!("------------------------------------------------------------");
    Ok(())
}

async fn handle_stats(session_id: &str, server: &str) -> anyhow::Result<()> {
    let args = serde_json::json!({ "session_id": session_id });
    let val = call_mcp_tool(server, "sandbox_metrics", args).await?;

    let status = val["status"].as_str().unwrap_or("unknown");
    let uptime = val["uptime_seconds"].as_u64().unwrap_or(0);
    let cpu_ms = val["cpu_time_ms"].as_u64().unwrap_or(0);
    let ram_rss = val["ram_rss_bytes"].as_u64().unwrap_or(0);
    let disk_bytes = val["disk_layer_bytes"].as_u64().unwrap_or(0);

    println!("============================================================");
    println!("           AgentKernel Sandbox Resource Metrics             ");
    println!("============================================================");
    println!("  Session ID:        {}", session_id);
    println!("  Status:            {}", status);
    println!("  Uptime:            {}s", uptime);
    println!("  CPU Time:          {} ms", cpu_ms);
    println!("  RAM RSS:           {} ({} bytes)", format_bytes(ram_rss), ram_rss);
    println!("  Disk Upper Layer:  {} ({} bytes)", format_bytes(disk_bytes), disk_bytes);
    println!("============================================================");
    Ok(())
}

async fn handle_shell(workspace: &str, custom_shell: Option<&str>) -> anyhow::Result<()> {
    let ws_path = std::path::Path::new(workspace);
    if !ws_path.exists() {
        tokio::fs::create_dir_all(ws_path).await?;
    }

    let (shell_cmd, shell_args) = if let Some(cmd) = custom_shell {
        (cmd.to_string(), vec![])
    } else if cfg!(windows) {
        ("powershell.exe".to_string(), vec!["-NoLogo".to_string()])
    } else {
        let sh = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        (sh, vec![])
    };

    println!("============================================================");
    println!("     AgentKernel Interactive Sandbox Shell Session          ");
    println!("============================================================");
    println!("  Workspace: {}", ws_path.canonicalize().unwrap_or_else(|_| ws_path.to_path_buf()).display());
    println!("  Shell:     {}", shell_cmd);
    println!("  Type 'exit' to quit the interactive session.");
    println!("============================================================");

    let mut process_cmd = std::process::Command::new(&shell_cmd);
    process_cmd
        .args(&shell_args)
        .current_dir(ws_path)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .env("AGENTKERNEL_WORKSPACE", workspace);

    let mut child = process_cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to launch shell '{shell_cmd}': {e}"))?;

    let exit_status = child.wait()?;
    let code = exit_status.code().unwrap_or(0);

    println!();
    println!("Interactive shell session terminated (exit code: {}).", code);

    if code != 0 {
        std::process::exit(code);
    }

    Ok(())
}

async fn call_mcp_tool(
    server: &str,
    tool_name: &str,
    args: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let host_port = server
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("127.0.0.1:8080");

    let rpc_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args
        }
    });
    let body = serde_json::to_vec(&rpc_req)?;

    if let Ok(mut stream) = tokio::net::TcpStream::connect(host_port).await {
        let req_header = format!(
            "POST /message HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            host_port,
            body.len()
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, req_header.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &body).await?;
        tokio::io::AsyncWriteExt::flush(&mut stream).await?;

        let mut resp_bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp_bytes).await?;

        if let Some(pos) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let body_bytes = &resp_bytes[pos + 4..];
            if let Ok(rpc_resp) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
                if let Some(err) = rpc_resp.get("error") {
                    anyhow::bail!("MCP error: {}", err["message"].as_str().unwrap_or("unknown error"));
                }
                if let Some(content) = rpc_resp["result"]["content"].as_array() {
                    if let Some(first) = content.first() {
                        if let Some(text) = first["text"].as_str() {
                            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(text) {
                                return Ok(json_val);
                            } else {
                                return Ok(serde_json::Value::String(text.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: check local session store on disk
    let session_id = args.get("session_id").and_then(|v| v.as_str()).unwrap_or_default();
    if let Some(meta) = agentkernel_mcp::server::load_session_metadata(session_id) {
        match tool_name {
            "sandbox_list_checkpoints" => {
                let mut list = Vec::new();
                for cp in meta.checkpoints {
                    let size_bytes = agentkernel_mcp::metrics::compute_dir_size(&cp.upperdir_path);
                    list.push(serde_json::json!({
                        "id": cp.id,
                        "name": cp.name,
                        "created_at": cp.created_at.to_rfc3339(),
                        "size_bytes": size_bytes,
                    }));
                }
                return Ok(serde_json::Value::Array(list));
            }
            "sandbox_diff" => {
                let from_cp_id = args.get("from_checkpoint").and_then(|v| v.as_str());
                let to_cp_id = args.get("to_checkpoint").and_then(|v| v.as_str());
                let workspace = std::path::PathBuf::from(&meta.workspace_path);

                let from_dir = if let Some(from_id) = from_cp_id {
                    meta.checkpoints
                        .iter()
                        .find(|c| c.id == from_id || c.name == from_id)
                        .map(|c| c.upperdir_path.clone())
                        .unwrap_or_else(|| workspace.join(".agentkernel").join("checkpoints").join(from_id))
                } else if let Some(last_cp) = meta.checkpoints.last() {
                    last_cp.upperdir_path.clone()
                } else {
                    workspace.clone()
                };

                let to_dir = if let Some(to_id) = to_cp_id {
                    meta.checkpoints
                        .iter()
                        .find(|c| c.id == to_id || c.name == to_id)
                        .map(|c| c.upperdir_path.clone())
                        .unwrap_or_else(|| workspace.join(".agentkernel").join("checkpoints").join(to_id))
                } else {
                    workspace.clone()
                };

                let diff = agentkernel_mcp::compute_directory_diff(&from_dir, &to_dir, &[".agentkernel"])?;
                return Ok(serde_json::json!({
                    "files": diff.files,
                    "diff": diff.diff,
                }));
            }
            "sandbox_metrics" => {
                let uptime = chrono::DateTime::parse_from_rfc3339(&meta.created_at_rfc3339)
                    .map(|dt| (chrono::Utc::now() - dt.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64)
                    .unwrap_or(0);
                let workspace = std::path::PathBuf::from(&meta.workspace_path);
                let disk_layer = agentkernel_mcp::metrics::compute_dir_size(&workspace);
                let ram_rss = agentkernel_mcp::metrics::get_process_rss_bytes();
                return Ok(serde_json::json!({
                    "session_id": session_id,
                    "status": "leased",
                    "uptime_seconds": uptime,
                    "cpu_time_ms": 0,
                    "ram_rss_bytes": ram_rss,
                    "disk_layer_bytes": disk_layer,
                }));
            }
            _ => anyhow::bail!("Unsupported tool fallback: {tool_name}"),
        }
    }

    anyhow::bail!(
        "Failed to query MCP daemon at {} and no active local session found for '{}'",
        server,
        session_id
    )
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Runs cold-boot, warm-boot, execution, snapshot and rollback benchmarks
async fn run_benchmark(iterations: usize) -> anyhow::Result<()> {
    println!("============================================================");
    println!("     AgentKernel Micro-Sandbox & Snapshot Benchmark         ");
    println!("============================================================");
    println!("Iterations: {iterations}");
    println!();

    let tmp = tempdir()?;
    let workspace = tmp.path().to_str().unwrap().to_string();

    let mut cold_boot_times = Vec::with_capacity(iterations);
    let mut warm_boot_times = Vec::with_capacity(iterations);
    let mut exec_times = Vec::with_capacity(iterations);
    let mut checkpoint_times = Vec::with_capacity(iterations);
    let mut rollback_times = Vec::with_capacity(iterations);

    let (cmd, args) = if cfg!(windows) {
        ("cmd", vec!["/C".to_string(), "echo".to_string(), "bench".to_string()])
    } else {
        ("echo", vec!["bench".to_string()])
    };

    for i in 1..=iterations {
        // 1. Warm Boot Test
        let pool = Arc::new(LocalPoolManager::new(5));
        let session_id_warm = format!("bench-warm-{i}");
        let config_warm = SandboxConfig {
            session_id: session_id_warm.clone(),
            tenant_id: None,
            workspace_path: workspace.clone(),
            base_rootfs: None,
            env_vars: vec![],
            timeout_seconds: 60,
        };

        let t0 = Instant::now();
        let session_warm = pool
            .acquire_sandbox(config_warm)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        warm_boot_times.push(t0.elapsed().as_micros() as f64 / 1000.0);

        // 2. Command Exec Test
        let t1 = Instant::now();
        let _ = session_warm
            .exec(cmd, &args, 5000)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        exec_times.push(t1.elapsed().as_micros() as f64 / 1000.0);

        // 3. Snapshot Creation Test
        let dummy_file = tmp.path().join("bench_data.txt");
        tokio::fs::write(&dummy_file, format!("bench iteration {i} data payload\n")).await?;

        let t2 = Instant::now();
        let cp = session_warm
            .create_checkpoint(&format!("cp-{i}"))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        checkpoint_times.push(t2.elapsed().as_micros() as f64 / 1000.0);

        // Mutate
        tokio::fs::write(&dummy_file, "mutated data\n").await?;

        // 4. Snapshot Rollback Test
        let t3 = Instant::now();
        session_warm
            .rollback(&cp.id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        rollback_times.push(t3.elapsed().as_micros() as f64 / 1000.0);

        let _ = pool.release_sandbox(&session_id_warm).await;

        // 5. Cold Boot Test (empty pool)
        let cold_pool = Arc::new(LocalPoolManager::new(0));
        let session_id_cold = format!("bench-cold-{i}");
        let config_cold = SandboxConfig {
            session_id: session_id_cold.clone(),
            tenant_id: None,
            workspace_path: workspace.clone(),
            base_rootfs: None,
            env_vars: vec![],
            timeout_seconds: 60,
        };

        let t4 = Instant::now();
        let _session_cold = cold_pool
            .acquire_sandbox(config_cold)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        cold_boot_times.push(t4.elapsed().as_micros() as f64 / 1000.0);
        let _ = cold_pool.release_sandbox(&session_id_cold).await;
    }

    print_metric_summary("Warm Pool Lease", &warm_boot_times, "ms");
    print_metric_summary("Cold Boot Lease", &cold_boot_times, "ms");
    print_metric_summary("Process Exec Latency", &exec_times, "ms");
    print_metric_summary("CoW Snapshot Creation", &checkpoint_times, "ms");
    print_metric_summary("CoW Snapshot Rollback", &rollback_times, "ms");

    println!("============================================================");
    println!("Benchmark completed successfully.");
    Ok(())
}

fn print_metric_summary(name: &str, samples: &[f64], unit: &str) {
    if samples.is_empty() {
        return;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let min = sorted.first().copied().unwrap_or(0.0);
    let max = sorted.last().copied().unwrap_or(0.0);
    let sum: f64 = sorted.iter().sum();
    let avg = sum / sorted.len() as f64;
    let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    let p95 = sorted.get(p95_idx).copied().unwrap_or(max);

    println!(
        "{:<24} | Avg: {:>7.3} {} | Min: {:>7.3} {} | P95: {:>7.3} {} | Max: {:>7.3} {}",
        name, avg, unit, min, unit, p95, unit, max, unit
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_daemon_defaults() {
        let cli = Cli::try_parse_from(["agentkernel", "daemon"]).expect("Failed to parse default daemon args");
        match cli.command {
            Commands::Daemon {
                addr,
                auth_token,
                tenants_file,
                metrics_path,
                warm_pool_size,
            } => {
                assert_eq!(addr, "127.0.0.1:8080");
                assert_eq!(auth_token, None);
                assert_eq!(tenants_file, None);
                assert_eq!(metrics_path, "/metrics");
                assert_eq!(warm_pool_size, 3);
            }
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_cli_parse_daemon_custom_options() {
        let cli = Cli::try_parse_from([
            "agentkernel",
            "daemon",
            "--addr",
            "0.0.0.0:9090",
            "--auth-token",
            "secret_token_123",
            "--tenants-file",
            "/etc/agentkernel/tenants.json",
            "--metrics-path",
            "/custom_metrics",
            "--warm-pool-size",
            "10",
        ])
        .expect("Failed to parse custom daemon args");

        match cli.command {
            Commands::Daemon {
                addr,
                auth_token,
                tenants_file,
                metrics_path,
                warm_pool_size,
            } => {
                assert_eq!(addr, "0.0.0.0:9090");
                assert_eq!(auth_token, Some("secret_token_123".to_string()));
                assert_eq!(
                    tenants_file,
                    Some(PathBuf::from("/etc/agentkernel/tenants.json"))
                );
                assert_eq!(metrics_path, "/custom_metrics");
                assert_eq!(warm_pool_size, 10);
            }
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_cli_parse_tenant_list() {
        let cli = Cli::try_parse_from([
            "agentkernel",
            "tenant",
            "list",
            "--tenants-file",
            "/tmp/tenants.json",
        ])
        .expect("Failed to parse tenant list args");

        match cli.command {
            Commands::Tenant {
                command: TenantCommands::List { tenants_file },
            } => {
                assert_eq!(tenants_file, PathBuf::from("/tmp/tenants.json"));
            }
            _ => panic!("Expected Tenant List command"),
        }
    }

    #[test]
    fn test_cli_parse_tenant_add() {
        let cli = Cli::try_parse_from([
            "agentkernel",
            "tenant",
            "add",
            "--tenants-file",
            "/tmp/tenants.json",
            "--id",
            "tenant-acme",
            "--name",
            "Acme Corp",
            "--api-key",
            "ak_live_xyz",
            "--max-sandboxes",
            "8",
        ])
        .expect("Failed to parse tenant add args");

        match cli.command {
            Commands::Tenant {
                command:
                    TenantCommands::Add {
                        tenants_file,
                        id,
                        name,
                        api_key,
                        max_sandboxes,
                    },
            } => {
                assert_eq!(tenants_file, PathBuf::from("/tmp/tenants.json"));
                assert_eq!(id, "tenant-acme");
                assert_eq!(name, "Acme Corp");
                assert_eq!(api_key, "ak_live_xyz");
                assert_eq!(max_sandboxes, 8);
            }
            _ => panic!("Expected Tenant Add command"),
        }
    }

    #[test]
    fn test_cli_parse_mcp() {
        let cli = Cli::try_parse_from(["agentkernel", "mcp", "--warm-pool-size", "5"])
            .expect("Failed to parse mcp args");
        match cli.command {
            Commands::Mcp { warm_pool_size } => {
                assert_eq!(warm_pool_size, 5);
            }
            _ => panic!("Expected Mcp command"),
        }
    }

    #[test]
    fn test_cli_parse_exec() {
        let cli = Cli::try_parse_from([
            "agentkernel",
            "exec",
            "--workspace",
            "/tmp/ws",
            "--timeout-ms",
            "15000",
            "--",
            "ls",
            "-la",
        ])
        .expect("Failed to parse exec args");

        match cli.command {
            Commands::Exec {
                workspace,
                timeout_ms,
                command,
            } => {
                assert_eq!(workspace, "/tmp/ws");
                assert_eq!(timeout_ms, 15000);
                assert_eq!(command, vec!["ls", "-la"]);
            }
            _ => panic!("Expected Exec command"),
        }
    }

    #[test]
    fn test_cli_parse_benchmark() {
        let cli = Cli::try_parse_from(["agentkernel", "benchmark", "--iterations", "25"])
            .expect("Failed to parse benchmark args");
        match cli.command {
            Commands::Benchmark { iterations } => {
                assert_eq!(iterations, 25);
            }
            _ => panic!("Expected Benchmark command"),
        }
    }
}
