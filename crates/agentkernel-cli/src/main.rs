//! AgentKernel CLI: Command-Line Interface for Micro-Sandbox & MCP Server.

use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::SandboxConfig;
use agentkernel_mcp::local_pool::LocalPoolManager;
use agentkernel_mcp::server::AgentKernelMcpServer;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tracing::info;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "agentkernel")]
#[command(about = "High-Performance Ephemeral Micro-Sandbox Runtime & MCP Server", version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Model Context Protocol (MCP) server over stdio
    Mcp {
        /// Number of pre-warmed sandbox isolates to maintain in pool
        #[arg(short, long, default_value = "3")]
        warm_pool_size: usize,
    },
    /// Start the MCP server daemon over HTTP/SSE
    Daemon {
        /// Socket address to listen on
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,

        /// Number of pre-warmed sandbox isolates
        #[arg(short, long, default_value = "3")]
        warm_pool_size: usize,
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
    /// Benchmark cold-boot latency and snapshot performance
    Benchmark {
        /// Number of iterations for benchmarking
        #[arg(short, long, default_value = "10")]
        iterations: usize,
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

        Commands::Daemon { addr, warm_pool_size } => {
            info!("Starting AgentKernel MCP daemon on http://{addr} (warm pool size: {warm_pool_size})...");
            let pool = Arc::new(LocalPoolManager::new(warm_pool_size));
            let server = AgentKernelMcpServer::new(pool);
            server.run_http_sse(&addr).await?;
        }

        Commands::Exec { workspace, timeout_ms, command } => {
            if command.is_empty() {
                anyhow::bail!("No command specified to execute");
            }

            let pool = Arc::new(LocalPoolManager::new(1));
            let session_id = format!("exec-{}", Uuid::new_v4());

            let config = SandboxConfig {
                session_id: session_id.clone(),
                workspace_path: workspace.clone(),
                base_rootfs: None,
                env_vars: vec![],
                timeout_seconds: (timeout_ms / 1000).max(1),
            };

            info!("Leasing sandbox for workspace: {workspace}...");
            let session = pool.acquire_sandbox(config).await
                .map_err(|e| anyhow::anyhow!("Sandbox acquisition failed: {e}"))?;

            let cmd = &command[0];
            let args = &command[1..];

            info!("Executing command: {cmd} {args:?} (timeout: {timeout_ms}ms)...");
            let output = session.exec(cmd, args, timeout_ms).await
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

        Commands::Benchmark { iterations } => {
            run_benchmark(iterations).await?;
        }
    }

    Ok(())
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
            workspace_path: workspace.clone(),
            base_rootfs: None,
            env_vars: vec![],
            timeout_seconds: 60,
        };

        let t0 = Instant::now();
        let session_warm = pool.acquire_sandbox(config_warm).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        warm_boot_times.push(t0.elapsed().as_micros() as f64 / 1000.0);

        // 2. Command Exec Test
        let t1 = Instant::now();
        let _ = session_warm.exec(cmd, &args, 5000).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        exec_times.push(t1.elapsed().as_micros() as f64 / 1000.0);

        // 3. Snapshot Creation Test
        let dummy_file = tmp.path().join("bench_data.txt");
        tokio::fs::write(&dummy_file, format!("bench iteration {i} data payload\n")).await?;

        let t2 = Instant::now();
        let cp = session_warm.create_checkpoint(&format!("cp-{i}")).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        checkpoint_times.push(t2.elapsed().as_micros() as f64 / 1000.0);

        // Mutate
        tokio::fs::write(&dummy_file, "mutated data\n").await?;

        // 4. Snapshot Rollback Test
        let t3 = Instant::now();
        session_warm.rollback(&cp.id).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        rollback_times.push(t3.elapsed().as_micros() as f64 / 1000.0);

        let _ = pool.release_sandbox(&session_id_warm).await;

        // 5. Cold Boot Test (empty pool)
        let cold_pool = Arc::new(LocalPoolManager::new(0));
        let session_id_cold = format!("bench-cold-{i}");
        let config_cold = SandboxConfig {
            session_id: session_id_cold.clone(),
            workspace_path: workspace.clone(),
            base_rootfs: None,
            env_vars: vec![],
            timeout_seconds: 60,
        };

        let t4 = Instant::now();
        let _session_cold = cold_pool.acquire_sandbox(config_cold).await
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

    println!("{:<24} | Avg: {:>7.3} {} | Min: {:>7.3} {} | P95: {:>7.3} {} | Max: {:>7.3} {}",
        name, avg, unit, min, unit, p95, unit, max, unit);
}
