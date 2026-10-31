use std::collections::VecDeque;

/// Configuration and factory for output truncation with LLM Token Guard.
#[derive(Debug, Clone)]
pub struct TokenGuard {
    head_limit: usize,
    tail_limit: usize,
    max_bytes: usize,
}

/// Result of output truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncateResult {
    pub content: String,
    pub truncated: bool,
    pub total_lines: usize,
    pub total_bytes: usize,
}

impl TokenGuard {
    /// Creates a TokenGuard splitting max_lines evenly between head and tail:
    /// head = (max_lines + 1) / 2, tail = max_lines / 2.
    /// If total lines exceed max_lines, it truncates keeping `head` lines at the top
    /// and `tail` lines at the bottom with a truncation marker in between.
    /// If max_lines is 0, no line truncation occurs.
    pub fn new(max_lines: usize) -> Self {
        let head = if max_lines > 0 { (max_lines + 1) / 2 } else { 0 };
        let tail = if max_lines > 0 { max_lines / 2 } else { 0 };
        Self {
            head_limit: head,
            tail_limit: tail,
            max_bytes: 10 * 1024 * 1024, // 10 MB default byte limit
        }
    }

    /// Creates a TokenGuard with explicit head and tail limits (e.g. first N and last N lines).
    pub fn with_head_tail(head_lines: usize, tail_lines: usize) -> Self {
        Self {
            head_limit: head_lines,
            tail_limit: tail_lines,
            max_bytes: 10 * 1024 * 1024,
        }
    }

    /// Sets the maximum byte limit.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Returns the head line limit.
    pub fn head_limit(&self) -> usize {
        self.head_limit
    }

    /// Returns the tail line limit.
    pub fn tail_limit(&self) -> usize {
        self.tail_limit
    }

    /// Returns the max byte limit.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Creates an active streaming ring-buffer.
    pub fn create_buffer(&self) -> TokenGuardRingBuffer {
        TokenGuardRingBuffer::new(self.head_limit, self.tail_limit, self.max_bytes)
    }

    /// Convenience method to truncate an already assembled multi-line string.
    pub fn truncate_string(&self, input: &str) -> TruncateResult {
        if input.is_empty() {
            return TruncateResult {
                content: String::new(),
                truncated: false,
                total_lines: 0,
                total_bytes: 0,
            };
        }

        let mut buffer = self.create_buffer();
        for line in input.lines() {
            buffer.push_line(line.to_string());
        }
        buffer.finish()
    }
}

/// Streaming ring-buffer for collecting process output with bounded memory usage.
#[derive(Debug)]
pub struct TokenGuardRingBuffer {
    head_limit: usize,
    tail_limit: usize,
    max_bytes: usize,
    head: Vec<String>,
    tail: VecDeque<String>,
    total_lines: usize,
    total_bytes: usize,
    truncated_by_bytes: bool,
}

impl TokenGuardRingBuffer {
    /// Creates a new streaming ring-buffer.
    pub fn new(head_limit: usize, tail_limit: usize, max_bytes: usize) -> Self {
        Self {
            head_limit,
            tail_limit,
            max_bytes,
            head: Vec::with_capacity(head_limit),
            tail: VecDeque::with_capacity(tail_limit),
            total_lines: 0,
            total_bytes: 0,
            truncated_by_bytes: false,
        }
    }

    /// Ingests a single output line into the buffer.
    pub fn push_line(&mut self, line: String) {
        self.total_lines += 1;
        self.total_bytes += line.len() + 1; // count characters plus newline

        if self.total_bytes > self.max_bytes {
            self.truncated_by_bytes = true;
            return;
        }

        if self.head_limit > 0 && self.head.len() < self.head_limit {
            self.head.push(line);
        } else if self.tail_limit > 0 {
            if self.tail.len() >= self.tail_limit {
                self.tail.pop_front();
            }
            self.tail.push_back(line);
        } else if self.head_limit == 0 && self.tail_limit == 0 {
            // Unlimited mode
            self.head.push(line);
        }
    }

    /// Returns the current total line count ingested.
    pub fn total_lines(&self) -> usize {
        self.total_lines
    }

    /// Returns the current total byte count ingested.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Finalizes the buffer and produces the truncated output.
    pub fn finish(self) -> TruncateResult {
        let max_allowed = self.head_limit + self.tail_limit;
        let line_limit_active = max_allowed > 0;
        let line_truncated = line_limit_active && self.total_lines > max_allowed;
        let truncated = line_truncated || self.truncated_by_bytes;

        let content = if line_truncated {
            let truncated_count = self.total_lines - self.head.len() - self.tail.len();
            let marker = format!("[... {} lines truncated ...]", truncated_count);

            let mut out = String::with_capacity(
                self.head.iter().map(|s| s.len() + 1).sum::<usize>()
                    + marker.len()
                    + 2
                    + self.tail.iter().map(|s| s.len() + 1).sum::<usize>(),
            );

            for (i, line) in self.head.iter().enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                out.push_str(line);
            }

            if !self.head.is_empty() {
                out.push('\n');
            }
            out.push_str(&marker);

            for line in &self.tail {
                out.push('\n');
                out.push_str(line);
            }

            out
        } else {
            let mut out = String::with_capacity(self.total_bytes);
            let mut first = true;
            for line in &self.head {
                if !first {
                    out.push('\n');
                }
                out.push_str(line);
                first = false;
            }
            for line in &self.tail {
                if !first {
                    out.push('\n');
                }
                out.push_str(line);
                first = false;
            }
            out
        };

        TruncateResult {
            content,
            truncated,
            total_lines: self.total_lines,
            total_bytes: self.total_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_guard_no_truncation() {
        let guard = TokenGuard::with_head_tail(3, 3);
        let input = "line 1\nline 2\nline 3\nline 4";
        let res = guard.truncate_string(input);

        assert!(!res.truncated);
        assert_eq!(res.total_lines, 4);
        assert_eq!(res.content, "line 1\nline 2\nline 3\nline 4");
    }

    #[test]
    fn test_token_guard_truncation_exact_marker() {
        let guard = TokenGuard::with_head_tail(2, 2);
        let lines: Vec<String> = (1..=10).map(|i| format!("line {}", i)).collect();
        let input = lines.join("\n");
        let res = guard.truncate_string(&input);

        assert!(res.truncated);
        assert_eq!(res.total_lines, 10);
        let expected = "line 1\nline 2\n[... 6 lines truncated ...]\nline 9\nline 10";
        assert_eq!(res.content, expected);
    }

    #[test]
    fn test_token_guard_new_split() {
        let guard = TokenGuard::new(4);
        assert_eq!(guard.head_limit(), 2);
        assert_eq!(guard.tail_limit(), 2);

        let lines: Vec<String> = (1..=6).map(|i| format!("line {}", i)).collect();
        let input = lines.join("\n");
        let res = guard.truncate_string(&input);

        assert!(res.truncated);
        assert_eq!(res.total_lines, 6);
        let expected = "line 1\nline 2\n[... 2 lines truncated ...]\nline 5\nline 6";
        assert_eq!(res.content, expected);
    }

    #[test]
    fn test_token_guard_empty_input() {
        let guard = TokenGuard::new(10);
        let res = guard.truncate_string("");
        assert!(!res.truncated);
        assert_eq!(res.total_lines, 0);
        assert_eq!(res.content, "");
    }

    #[test]
    fn test_token_guard_byte_limit() {
        let guard = TokenGuard::new(100).with_max_bytes(20);
        let lines: Vec<String> = (1..=10).map(|i| format!("line with lots of text {}", i)).collect();
        let input = lines.join("\n");
        let res = guard.truncate_string(&input);

        assert!(res.truncated);
    }
}
