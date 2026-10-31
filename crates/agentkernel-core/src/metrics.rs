//! Thread-safe Prometheus Metrics Registry & Collector for AgentKernel.
//! Generates standard Prometheus text exposition format (version 0.0.4).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Thread-safe Prometheus Gauge metric.
#[derive(Debug, Default)]
pub struct Gauge {
    val: AtomicI64,
}

impl Gauge {
    pub fn new(initial: i64) -> Self {
        Self {
            val: AtomicI64::new(initial),
        }
    }

    pub fn set(&self, v: i64) {
        self.val.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.val.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.val.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add(&self, v: i64) {
        self.val.fetch_add(v, Ordering::Relaxed);
    }

    pub fn sub(&self, v: i64) {
        self.val.fetch_sub(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.val.load(Ordering::Relaxed)
    }
}

/// Thread-safe Prometheus Counter metric.
#[derive(Debug, Default)]
pub struct Counter {
    val: AtomicU64,
}

impl Counter {
    pub fn new(initial: u64) -> Self {
        Self {
            val: AtomicU64::new(initial),
        }
    }

    pub fn inc(&self) {
        self.val.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, v: u64) {
        self.val.fetch_add(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.val.load(Ordering::Relaxed)
    }
}

/// Standard latency bucket thresholds in seconds.
pub const DEFAULT_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Thread-safe Prometheus Histogram metric.
pub struct Histogram {
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: RwLock<f64>,
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::with_buckets(DEFAULT_BUCKETS)
    }
}

impl Histogram {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_buckets(buckets: &[f64]) -> Self {
        let mut sorted = buckets.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let counts: Vec<AtomicU64> = (0..sorted.len()).map(|_| AtomicU64::new(0)).collect();

        Self {
            buckets: sorted,
            bucket_counts: counts,
            sum: RwLock::new(0.0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut sum_guard) = self.sum.write() {
            *sum_guard += value;
        }

        for (i, &upper) in self.buckets.iter().enumerate() {
            if value <= upper {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_secs_f64());
    }

    pub fn start_timer(&self) -> HistogramTimer<'_> {
        HistogramTimer {
            histogram: self,
            start: Instant::now(),
        }
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum(&self) -> f64 {
        self.sum.read().map(|s| *s).unwrap_or(0.0)
    }

    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    pub fn bucket_counts(&self) -> Vec<u64> {
        self.bucket_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }
}

/// RAII timer that records elapsed duration to a Histogram on drop.
pub struct HistogramTimer<'a> {
    histogram: &'a Histogram,
    start: Instant,
}

impl<'a> Drop for HistogramTimer<'a> {
    fn drop(&mut self) {
        self.histogram.observe_duration(self.start.elapsed());
    }
}

/// Central Metrics Registry for AgentKernel runtime and MCP services.
#[derive(Clone)]
pub struct MetricsRegistry {
    // Gauges
    pub sandboxes_warm: Arc<Gauge>,
    pub sandboxes_leased: Arc<Gauge>,
    pub sandboxes_total: Arc<Gauge>,

    // Counters
    pub cold_boot_total: Arc<Counter>,
    pub warm_boot_total: Arc<Counter>,
    pub commands_total: Arc<Counter>,
    pub quota_violations_total: Arc<Counter>,

    // Histograms
    pub cold_boot_duration_seconds: Arc<Histogram>,
    pub checkpoint_duration_seconds: Arc<Histogram>,
    pub rollback_duration_seconds: Arc<Histogram>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            sandboxes_warm: Arc::new(Gauge::new(0)),
            sandboxes_leased: Arc::new(Gauge::new(0)),
            sandboxes_total: Arc::new(Gauge::new(0)),
            cold_boot_total: Arc::new(Counter::new(0)),
            warm_boot_total: Arc::new(Counter::new(0)),
            commands_total: Arc::new(Counter::new(0)),
            quota_violations_total: Arc::new(Counter::new(0)),
            cold_boot_duration_seconds: Arc::new(Histogram::new()),
            checkpoint_duration_seconds: Arc::new(Histogram::new()),
            rollback_duration_seconds: Arc::new(Histogram::new()),
        }
    }

    /// Renders all registered metrics in standard Prometheus text exposition format (version 0.0.4).
    pub fn render_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Gauges
        Self::render_gauge(
            &mut out,
            "agentkernel_sandboxes_warm",
            "Current number of pre-warmed sandboxes in the pool",
            self.sandboxes_warm.get(),
        );

        Self::render_gauge(
            &mut out,
            "agentkernel_sandboxes_leased",
            "Current number of actively leased sandboxes",
            self.sandboxes_leased.get(),
        );

        Self::render_gauge(
            &mut out,
            "agentkernel_sandboxes_total",
            "Total number of sandboxes managed by the kernel",
            self.sandboxes_total.get(),
        );

        // Counters
        Self::render_counter(
            &mut out,
            "agentkernel_cold_boot_total",
            "Total count of cold sandbox boot operations",
            self.cold_boot_total.get(),
        );

        Self::render_counter(
            &mut out,
            "agentkernel_warm_boot_total",
            "Total count of warm sandbox boot operations from pool",
            self.warm_boot_total.get(),
        );

        Self::render_counter(
            &mut out,
            "agentkernel_commands_total",
            "Total count of commands executed inside sandboxes",
            self.commands_total.get(),
        );

        Self::render_counter(
            &mut out,
            "agentkernel_quota_violations_total",
            "Total count of tenant quota violations blocked",
            self.quota_violations_total.get(),
        );

        // Histograms
        Self::render_histogram(
            &mut out,
            "agentkernel_cold_boot_duration_seconds",
            "Duration of cold sandbox boot operations in seconds",
            &self.cold_boot_duration_seconds,
        );

        Self::render_histogram(
            &mut out,
            "agentkernel_checkpoint_duration_seconds",
            "Duration of checkpoint snapshot creation in seconds",
            &self.checkpoint_duration_seconds,
        );

        Self::render_histogram(
            &mut out,
            "agentkernel_rollback_duration_seconds",
            "Duration of checkpoint rollback operations in seconds",
            &self.rollback_duration_seconds,
        );

        out
    }

    fn render_gauge(out: &mut String, name: &str, help: &str, value: i64) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} gauge\n"));
        out.push_str(&format!("{name} {value}\n\n"));
    }

    fn render_counter(out: &mut String, name: &str, help: &str, value: u64) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} counter\n"));
        out.push_str(&format!("{name} {value}\n\n"));
    }

    fn render_histogram(out: &mut String, name: &str, help: &str, hist: &Histogram) {
        out.push_str(&format!("# HELP {name} {help}\n"));
        out.push_str(&format!("# TYPE {name} histogram\n"));

        let buckets = hist.buckets();
        let counts = hist.bucket_counts();
        let total_count = hist.get_count();
        let sum = hist.get_sum();

        // Cumulative counts for buckets
        let mut cumulative = 0u64;
        for (i, &le) in buckets.iter().enumerate() {
            cumulative += counts[i];
            out.push_str(&format!("{name}_bucket{{le=\"{le}\"}} {cumulative}\n"));
        }
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {total_count}\n"));
        out.push_str(&format!("{name}_sum {sum:.6}\n"));
        out.push_str(&format!("{name}_count {total_count}\n\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gauge_operations() {
        let g = Gauge::new(5);
        assert_eq!(g.get(), 5);
        g.inc();
        assert_eq!(g.get(), 6);
        g.dec();
        assert_eq!(g.get(), 5);
        g.add(10);
        assert_eq!(g.get(), 15);
        g.sub(3);
        assert_eq!(g.get(), 12);
        g.set(100);
        assert_eq!(g.get(), 100);
    }

    #[test]
    fn test_counter_operations() {
        let c = Counter::new(0);
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        assert_eq!(c.get(), 2);
        c.inc_by(8);
        assert_eq!(c.get(), 10);
    }

    #[test]
    fn test_histogram_and_timer() {
        let h = Histogram::with_buckets(&[0.01, 0.05, 0.1, 1.0]);
        h.observe(0.005);
        h.observe(0.02);
        h.observe(0.2);

        assert_eq!(h.get_count(), 3);
        assert!(h.get_sum() >= 0.22);

        {
            let _t = h.start_timer();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(h.get_count(), 4);
    }

    #[test]
    fn test_metrics_registry_render() {
        let reg = MetricsRegistry::new();
        reg.sandboxes_warm.set(3);
        reg.sandboxes_leased.set(2);
        reg.sandboxes_total.set(5);
        reg.cold_boot_total.inc_by(4);
        reg.warm_boot_total.inc_by(10);
        reg.commands_total.inc_by(42);
        reg.quota_violations_total.inc_by(1);

        reg.cold_boot_duration_seconds.observe(0.025);
        reg.checkpoint_duration_seconds.observe(0.005);
        reg.rollback_duration_seconds.observe(0.003);

        let rendered = reg.render_prometheus_metrics();

        assert!(rendered.contains("# HELP agentkernel_sandboxes_warm"));
        assert!(rendered.contains("# TYPE agentkernel_sandboxes_warm gauge"));
        assert!(rendered.contains("agentkernel_sandboxes_warm 3"));

        assert!(rendered.contains("# HELP agentkernel_sandboxes_leased"));
        assert!(rendered.contains("agentkernel_sandboxes_leased 2"));

        assert!(rendered.contains("# HELP agentkernel_sandboxes_total"));
        assert!(rendered.contains("agentkernel_sandboxes_total 5"));

        assert!(rendered.contains("# HELP agentkernel_cold_boot_total"));
        assert!(rendered.contains("agentkernel_cold_boot_total 4"));

        assert!(rendered.contains("# HELP agentkernel_warm_boot_total"));
        assert!(rendered.contains("agentkernel_warm_boot_total 10"));

        assert!(rendered.contains("# HELP agentkernel_commands_total"));
        assert!(rendered.contains("agentkernel_commands_total 42"));

        assert!(rendered.contains("# HELP agentkernel_quota_violations_total"));
        assert!(rendered.contains("agentkernel_quota_violations_total 1"));

        assert!(rendered.contains("# TYPE agentkernel_cold_boot_duration_seconds histogram"));
        assert!(rendered.contains("agentkernel_cold_boot_duration_seconds_count 1"));

        assert!(rendered.contains("# TYPE agentkernel_checkpoint_duration_seconds histogram"));
        assert!(rendered.contains("agentkernel_checkpoint_duration_seconds_count 1"));

        assert!(rendered.contains("# TYPE agentkernel_rollback_duration_seconds histogram"));
        assert!(rendered.contains("agentkernel_rollback_duration_seconds_count 1"));
    }
}
