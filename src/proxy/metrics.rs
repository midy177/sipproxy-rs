use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

const METRIC_SHARDS: usize = 64;

#[derive(Debug)]
pub struct ProxyMetrics {
    shards: Vec<Mutex<HashMap<String, Counter>>>,
}

#[derive(Debug, Clone)]
struct Counter {
    name: String,
    labels: Vec<(String, String)>,
    value: u64,
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self {
            shards: (0..METRIC_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }
}

impl ProxyMetrics {
    pub fn incr(&self, name: &'static str, labels: &[(&'static str, &str)]) {
        let key = counter_key(name, labels);
        let mut counters = self.shards[metric_shard_index(&key)]
            .lock()
            .expect("metrics mutex poisoned");
        counters
            .entry(key)
            .and_modify(|counter| counter.value += 1)
            .or_insert(Counter {
                name: name.to_string(),
                labels: labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
                value: 1,
            });
    }

    pub fn render_prometheus(&self) -> String {
        let mut values = Vec::new();
        for shard in &self.shards {
            let counters = shard.lock().expect("metrics mutex poisoned");
            values.extend(counters.values().cloned());
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
}
