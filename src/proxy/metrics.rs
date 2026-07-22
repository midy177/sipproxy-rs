use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::collections::hash_map::Entry;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const METRIC_SHARDS: usize = 64;

#[derive(Debug)]
pub struct ProxyMetrics {
    shards: Vec<RwLock<HashMap<String, Arc<Counter>>>>,
}

#[derive(Debug, Clone)]
pub struct CounterHandle {
    counter: Arc<Counter>,
}

#[derive(Debug)]
struct Counter {
    name: String,
    labels: Vec<(String, String)>,
    value: AtomicU64,
}

#[derive(Debug)]
struct CounterSnapshot {
    name: String,
    labels: Vec<(String, String)>,
    value: u64,
}

impl CounterHandle {
    pub fn incr(&self) {
        self.counter.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_by(&self, value: u64) {
        self.counter.value.fetch_add(value, Ordering::Relaxed);
    }
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self {
            shards: (0..METRIC_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
        }
    }
}

impl ProxyMetrics {
    pub fn incr(&self, name: &'static str, labels: &[(&'static str, &str)]) {
        self.counter_arc(name, labels)
            .value
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn incr_by(&self, name: &'static str, labels: &[(&'static str, &str)], value: u64) {
        self.counter_arc(name, labels)
            .value
            .fetch_add(value, Ordering::Relaxed);
    }

    pub fn counter(&self, name: &'static str, labels: &[(&'static str, &str)]) -> CounterHandle {
        CounterHandle {
            counter: self.counter_arc(name, labels),
        }
    }

    fn counter_arc(&self, name: &'static str, labels: &[(&'static str, &str)]) -> Arc<Counter> {
        let key = counter_key(name, labels);
        let shard = &self.shards[metric_shard_index(&key)];
        {
            let counters = shard.read().expect("metrics rwlock poisoned");
            if let Some(counter) = counters.get(&key) {
                return counter.clone();
            }
        }

        let mut counters = shard.write().expect("metrics rwlock poisoned");
        match counters.entry(key) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => entry
                .insert(Arc::new(Counter {
                    name: name.to_string(),
                    labels: labels
                        .iter()
                        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                        .collect(),
                    value: AtomicU64::new(0),
                }))
                .clone(),
        }
    }

    pub fn render_prometheus(&self) -> String {
        let mut values = Vec::new();
        for shard in &self.shards {
            let counters = shard.read().expect("metrics rwlock poisoned");
            values.extend(counters.values().filter_map(|counter| {
                let value = counter.value.load(Ordering::Relaxed);
                (value > 0).then(|| CounterSnapshot {
                    name: counter.name.clone(),
                    labels: counter.labels.clone(),
                    value,
                })
            }));
        }
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.labels.cmp(&right.labels))
        });

        let mut output = String::new();
        let mut last_name = None::<String>;
        for counter in values {
            if last_name.as_deref() != Some(counter.name.as_str()) {
                output.push_str("# TYPE ");
                output.push_str(&counter.name);
                output.push_str(" counter\n");
                last_name = Some(counter.name.clone());
            }
            output.push_str(&counter.name);
            if !counter.labels.is_empty() {
                output.push('{');
                for (index, (key, value)) in counter.labels.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(key);
                    output.push_str("=\"");
                    output.push_str(&escape_label_value(value));
                    output.push('"');
                }
                output.push('}');
            }
            output.push(' ');
            output.push_str(&counter.value.to_string());
            output.push('\n');
        }
        output
    }
}

fn counter_key(name: &str, labels: &[(&str, &str)]) -> String {
    let mut key = name.to_string();
    for (label, value) in labels {
        key.push('|');
        key.push_str(label);
        key.push('=');
        key.push_str(value);
    }
    key
}

fn metric_shard_index(key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize % METRIC_SHARDS
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn renders_prometheus_counters() {
        let metrics = ProxyMetrics::default();
        metrics.incr(
            "sip_requests_total",
            &[("transport", "udp"), ("method", "INVITE")],
        );
        metrics.incr(
            "sip_requests_total",
            &[("transport", "udp"), ("method", "INVITE")],
        );
        metrics.incr(
            "sip_requests_total",
            &[("transport", "tcp"), ("method", "MESSAGE")],
        );

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("# TYPE sip_requests_total counter"));
        assert!(rendered.contains("sip_requests_total{transport=\"udp\",method=\"INVITE\"} 2"));
        assert!(rendered.contains("sip_requests_total{transport=\"tcp\",method=\"MESSAGE\"} 1"));
    }

    #[test]
    fn concurrent_counter_increments_are_preserved() {
        let metrics = Arc::new(ProxyMetrics::default());
        let mut workers = Vec::new();
        for worker in 0..8 {
            let metrics = metrics.clone();
            workers.push(thread::spawn(move || {
                let method = if worker % 2 == 0 {
                    "INVITE"
                } else {
                    "REGISTER"
                };
                for _ in 0..1_000 {
                    metrics.incr(
                        "sip_requests_total",
                        &[("transport", "udp"), ("method", method)],
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("sip_requests_total{transport=\"udp\",method=\"INVITE\"} 4000"));
        assert!(
            rendered.contains("sip_requests_total{transport=\"udp\",method=\"REGISTER\"} 4000")
        );
    }

    #[test]
    fn counter_handles_do_not_render_until_incremented() {
        let metrics = ProxyMetrics::default();
        let counter = metrics.counter(
            "sip_requests_total",
            &[("transport", "udp"), ("method", "OPTIONS")],
        );

        assert!(!metrics.render_prometheus().contains("sip_requests_total"));

        counter.incr();
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("sip_requests_total{transport=\"udp\",method=\"OPTIONS\"} 1"));
    }
}
