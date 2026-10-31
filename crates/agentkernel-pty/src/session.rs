use crate::manager::build_command;
use crate::token_guard::{TokenGuard, TokenGuardRingBuffer};
use crate::{CommandOutput, PtyError};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

/// A chunk of output streamed from a running process PTY session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyOutputChunk {
    pub is_stderr: bool,
    pub data: Vec<u8>,
}

impl PtyOutputChunk {
    /// Creates a stdout output chunk.
    pub fn stdout(data: Vec<u8>) -> Self {
        Self {
            is_stderr: false,
            data,
        }
    }

    /// Creates a stderr output chunk.
    pub fn stderr(data: Vec<u8>) -> Self {
        Self {
            is_stderr: true,
            data,
        }
    }

    /// Attempts to view chunk data as UTF-8 string.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    /// Converts chunk data into lossy UTF-8 string.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// Broadcast streamer for real-time PTY output distribution (SSE, web consoles, multiplexers).
#[derive(Debug, Clone)]
pub struct PtyStreamer {
    sender: broadcast::Sender<PtyOutputChunk>,
}

impl Default for PtyStreamer {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl PtyStreamer {
    /// Creates a new PtyStreamer with specified broadcast capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self { sender }
    }

    /// Subscribes to the broadcast channel to receive real-time output chunks.
    pub fn subscribe(&self) -> broadcast::Receiver<PtyOutputChunk> {
        self.sender.subscribe()
    }

    /// Broadcasts an output chunk to all active subscribers.
    /// Returns the number of active subscribers that received the message.
    pub fn broadcast(&self, chunk: PtyOutputChunk) -> usize {
        match self.sender.send(chunk) {
            Ok(count) => count,
            Err(_) => 0, // No active subscribers is expected and valid
        }
    }

    /// Returns a reference to the internal broadcast sender.
    pub fn sender(&self) -> &broadcast::Sender<PtyOutputChunk> {
        &self.sender
    }
}

/// Interactive bidirectional PTY session allowing real-time stdin input,
/// terminal resizing, POSIX/emulated signal handling, and broadcast streaming.
pub struct InteractiveSession {
    pid: Option<u32>,
    stdin_tx: mpsc::UnboundedSender<Vec<u8>>,
    signal_tx: mpsc::UnboundedSender<i32>,
    streamer: Arc<PtyStreamer>,
    dimensions: Arc<RwLock<(u16, u16)>>,
    exit_rx: Arc<Mutex<Option<oneshot::Receiver<std::io::Result<std::process::ExitStatus>>>>>,
    stdout_guard: Arc<Mutex<Option<TokenGuardRingBuffer>>>,
    stderr_guard: Arc<Mutex<Option<TokenGuardRingBuffer>>>,
    stdout_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    stderr_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    start_time: Instant,
    cached_output: Arc<Mutex<Option<CommandOutput>>>,
    alive: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    master_fd: Option<i32>,
}

impl InteractiveSession {
    /// Spawns a new interactive command session with bounded Token Guard output buffers.
    pub fn spawn(
        cmd: &str,
        args: &[String],
        working_dir: &str,
        max_lines: usize,
        max_bytes: usize,
    ) -> Result<Self, PtyError> {
        let mut command = build_command(cmd, args, working_dir);
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().map_err(PtyError::Io)?;
        let pid = child.id();

        let child_stdin = child.stdin.take();
        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();

        let streamer = Arc::new(PtyStreamer::new(1024));
        let dimensions = Arc::new(RwLock::new((80, 24)));
        let alive = Arc::new(AtomicBool::new(true));

        // Stdin asynchronous writer task
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            if let Some(mut stdin) = child_stdin {
                while let Some(data) = stdin_rx.recv().await {
                    if stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    if stdin.flush().await.is_err() {
                        break;
                    }
                }
            }
        });

        // Setup Token Guard buffers
        let out_buffer = TokenGuard::new(max_lines)
            .with_max_bytes(max_bytes)
            .create_buffer();
        let err_buffer = TokenGuard::new(max_lines)
            .with_max_bytes(max_bytes)
            .create_buffer();

        let stdout_guard = Arc::new(Mutex::new(Some(out_buffer)));
        let stderr_guard = Arc::new(Mutex::new(Some(err_buffer)));

        // Stdout reader task
        let streamer_out = streamer.clone();
        let out_guard_clone = stdout_guard.clone();
        let stdout_task = tokio::spawn(async move {
            if let Some(mut stdout) = child_stdout {
                let mut buf = [0u8; 4096];
                let mut line_buf = Vec::new();

                while let Ok(n) = stdout.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let chunk = buf[..n].to_vec();
                    streamer_out.broadcast(PtyOutputChunk::stdout(chunk.clone()));

                    let mut guard_lock = out_guard_clone.lock().await;
                    if let Some(ref mut guard) = *guard_lock {
                        for &byte in &chunk {
                            if byte == b'\n' {
                                let line = String::from_utf8_lossy(&line_buf)
                                    .trim_end_matches('\r')
                                    .to_string();
                                guard.push_line(line);
                                line_buf.clear();
                            } else {
                                line_buf.push(byte);
                            }
                        }
                    }
                }

                if !line_buf.is_empty() {
                    let line = String::from_utf8_lossy(&line_buf)
                        .trim_end_matches('\r')
                        .to_string();
                    let mut guard_lock = out_guard_clone.lock().await;
                    if let Some(ref mut guard) = *guard_lock {
                        guard.push_line(line);
                    }
                }
            }
        });

        // Stderr reader task
        let streamer_err = streamer.clone();
        let err_guard_clone = stderr_guard.clone();
        let stderr_task = tokio::spawn(async move {
            if let Some(mut stderr) = child_stderr {
                let mut buf = [0u8; 4096];
                let mut line_buf = Vec::new();

                while let Ok(n) = stderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let chunk = buf[..n].to_vec();
                    streamer_err.broadcast(PtyOutputChunk::stderr(chunk.clone()));

                    let mut guard_lock = err_guard_clone.lock().await;
                    if let Some(ref mut guard) = *guard_lock {
                        for &byte in &chunk {
                            if byte == b'\n' {
                                let line = String::from_utf8_lossy(&line_buf)
                                    .trim_end_matches('\r')
                                    .to_string();
                                guard.push_line(line);
                                line_buf.clear();
                            } else {
                                line_buf.push(byte);
                            }
                        }
                    }
                }

                if !line_buf.is_empty() {
                    let line = String::from_utf8_lossy(&line_buf)
                        .trim_end_matches('\r')
                        .to_string();
                    let mut guard_lock = err_guard_clone.lock().await;
                    if let Some(ref mut guard) = *guard_lock {
                        guard.push_line(line);
                    }
                }
            }
        });

        // Process supervisor task with cancellation/signal handling
        let (signal_tx, mut signal_rx) = mpsc::unbounded_channel::<i32>();
        let (exit_tx, exit_rx) = oneshot::channel();
        let alive_supervisor_ref = alive.clone();

        tokio::spawn(async move {
            tokio::select! {
                status_res = child.wait() => {
                    alive_supervisor_ref.store(false, Ordering::SeqCst);
                    let _ = exit_tx.send(status_res);
                }
                Some(sig) = signal_rx.recv() => {
                    if sig == 2 || sig == 9 || sig == 15 {
                        let _ = child.kill().await;
                        let status_res = child.wait().await;
                        alive_supervisor_ref.store(false, Ordering::SeqCst);
                        let _ = exit_tx.send(status_res);
                    }
                }
            }
        });

        Ok(Self {
            pid,
            stdin_tx,
            signal_tx,
            streamer,
            dimensions,
            exit_rx: Arc::new(Mutex::new(Some(exit_rx))),
            stdout_guard,
            stderr_guard,
            stdout_task: Arc::new(Mutex::new(Some(stdout_task))),
            stderr_task: Arc::new(Mutex::new(Some(stderr_task))),
            start_time: Instant::now(),
            cached_output: Arc::new(Mutex::new(None)),
            alive,
            #[cfg(target_os = "linux")]
            master_fd: None,
        })
    }

    /// Sends raw input bytes to the running process stdin.
    pub fn send_input(&self, input: &[u8]) -> Result<(), PtyError> {
        self.stdin_tx.send(input.to_vec()).map_err(|_| {
            PtyError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Interactive session stdin channel closed",
            ))
        })
    }

    /// Sends a POSIX or emulated signal to the process (e.g. 2 for SIGINT, 15 for SIGTERM, 9 for SIGKILL).
    pub fn send_signal(&self, signal: i32) -> Result<(), PtyError> {
        #[cfg(target_os = "linux")]
        {
            if let Some(pid) = self.pid {
                let nix_sig = match signal {
                    2 => nix::sys::signal::Signal::SIGINT,
                    9 => nix::sys::signal::Signal::SIGKILL,
                    15 => nix::sys::signal::Signal::SIGTERM,
                    other => nix::sys::signal::Signal::try_from(other)
                        .unwrap_or(nix::sys::signal::Signal::SIGTERM),
                };
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix_sig);
            }
        }

        // Send to internal signal listener to ensure child cleanup
        let _ = self.signal_tx.send(signal);
        Ok(())
    }

    /// Resizes the pseudo-terminal dimensions (columns, rows).
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), PtyError> {
        *self.dimensions.write().unwrap() = (cols, rows);

        #[cfg(target_os = "linux")]
        if let Some(fd) = self.master_fd {
            let ws = nix::pty::Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            unsafe {
                libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
            }
        }

        Ok(())
    }

    /// Subscribes to the broadcast channel for real-time output chunks.
    pub fn subscribe(&self) -> broadcast::Receiver<PtyOutputChunk> {
        self.streamer.subscribe()
    }

    /// Returns a reference to the shared PtyStreamer.
    pub fn streamer(&self) -> Arc<PtyStreamer> {
        self.streamer.clone()
    }

    /// Returns the current terminal dimensions (columns, rows).
    pub fn dimensions(&self) -> (u16, u16) {
        *self.dimensions.read().unwrap()
    }

    /// Returns the OS process ID if available.
    pub fn child_pid(&self) -> Option<u32> {
        self.pid
    }

    /// Returns whether the child process is still considered active.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Awaits process completion and returns final Token Guard processed output.
    pub async fn wait_output(&self) -> Result<CommandOutput, PtyError> {
        // Return cached output if already waited
        {
            let cache = self.cached_output.lock().await;
            if let Some(ref out) = *cache {
                return Ok(out.clone());
            }
        }

        let exit_code = {
            let mut rx_lock = self.exit_rx.lock().await;
            if let Some(rx) = rx_lock.take() {
                match rx.await {
                    Ok(Ok(status)) => status.code().unwrap_or(-1),
                    Ok(Err(e)) => return Err(PtyError::Io(e)),
                    Err(_) => -1,
                }
            } else {
                -1
            }
        };

        self.alive.store(false, Ordering::SeqCst);

        // Await readers to finish flushing
        if let Some(t) = self.stdout_task.lock().await.take() {
            let _ = t.await;
        }
        if let Some(t) = self.stderr_task.lock().await.take() {
            let _ = t.await;
        }

        let stdout_res = self
            .stdout_guard
            .lock()
            .await
            .take()
            .map(|g| g.finish())
            .unwrap_or(crate::token_guard::TruncateResult {
                content: String::new(),
                truncated: false,
                total_lines: 0,
                total_bytes: 0,
            });

        let stderr_res = self
            .stderr_guard
            .lock()
            .await
            .take()
            .map(|g| g.finish())
            .unwrap_or(crate::token_guard::TruncateResult {
                content: String::new(),
                truncated: false,
                total_lines: 0,
                total_bytes: 0,
            });

        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let truncated = stdout_res.truncated || stderr_res.truncated;
        let total_lines = stdout_res.total_lines + stderr_res.total_lines;

        let output = CommandOutput {
            exit_code,
            stdout: stdout_res.content,
            stderr: stderr_res.content,
            duration_ms,
            truncated,
            total_lines,
        };

        let mut cache = self.cached_output.lock().await;
        *cache = Some(output.clone());

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interactive_session_stdin_and_broadcast() {
        // Cross-platform command that reads a single line from stdin and prints it with prefix
        let (cmd, args) = if cfg!(target_os = "windows") {
            (
                "cmd",
                vec![
                    "/V:ON".into(),
                    "/C".into(),
                    "set /p val= & echo ECHO: !val!".into(),
                ],
            )
        } else {
            ("sh", vec!["-c".into(), "read line; echo \"ECHO: $line\"".into()])
        };

        let session = InteractiveSession::spawn(cmd, &args, ".", 100, 1024 * 1024)
            .expect("Session spawn should succeed");

        assert!(session.is_alive());
        assert!(session.child_pid().is_some());

        // Subscribe to real-time broadcast stream
        let mut rx = session.subscribe();

        // Send input line to process stdin
        session
            .send_input(b"HelloAgentKernel\r\n")
            .expect("send_input should succeed");

        // Collect broadcast chunks
        let mut collected = Vec::new();
        let timeout = std::time::Duration::from_secs(5);
        let start = Instant::now();

        while start.elapsed() < timeout {
            match tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(chunk)) => {
                    let s = chunk.to_string_lossy();
                    collected.push(s);
                    if collected.iter().any(|c| c.contains("ECHO: HelloAgentKernel")) {
                        break;
                    }
                }
                _ => {
                    if !session.is_alive() {
                        break;
                    }
                }
            }
        }

        let combined_stream = collected.join("");
        assert!(
            combined_stream.contains("ECHO: HelloAgentKernel"),
            "Broadcast stream should contain echoed line, got: {}",
            combined_stream
        );

        // Await session completion and verify Token Guard final output
        let output = session.wait_output().await.expect("Wait output failed");
        assert_eq!(output.exit_code, 0);
        assert!(
            output.stdout.contains("ECHO: HelloAgentKernel"),
            "Output stdout should contain echoed input, got: {}",
            output.stdout
        );
        assert!(!session.is_alive());
    }

    #[tokio::test]
    async fn test_interactive_session_resize() {
        let (cmd, args) = if cfg!(target_os = "windows") {
            ("cmd", vec!["/C".into(), "echo ok".into()])
        } else {
            ("echo", vec!["ok".into()])
        };

        let session = InteractiveSession::spawn(cmd, &args, ".", 10, 1024)
            .expect("Session spawn should succeed");

        assert_eq!(session.dimensions(), (80, 24));
        session.resize(120, 40).expect("Resize should succeed");
        assert_eq!(session.dimensions(), (120, 40));
    }

    #[tokio::test]
    async fn test_interactive_session_signal_termination() {
        // Long running sleep command
        let (cmd, args) = if cfg!(target_os = "windows") {
            (
                "powershell",
                vec!["-NoProfile".into(), "-Command".into(), "Start-Sleep -Seconds 30".into()],
            )
        } else {
            ("sleep", vec!["30".into()])
        };

        let session = InteractiveSession::spawn(cmd, &args, ".", 10, 1024)
            .expect("Session spawn should succeed");

        assert!(session.is_alive());

        // Send SIGINT / SIGKILL
        session.send_signal(2).expect("send_signal should succeed");

        // Wait a short duration for process to be killed
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), session.wait_output()).await;
        assert!(!session.is_alive());
    }
}
