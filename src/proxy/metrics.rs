use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct ProxyMetrics {
    counters: Mutex<HashMap<String, Counter>>,
}

#[derive(Debug, Clone)]
struct Counter {
    name: String,
    labels: Vec<(String, String)>,
    value: u64,
}

impl ProxyMetrics {
    pub fn incr(&self, name: &'static str, labels: &[(&'static str, &str)]) {
        let labels = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<Vec<_>>();
        let key = counter_key(name, &labels);
        let mut counters = self.counters.lock().expect("metrics mutex poisoned");
        counters
            .entry(key)
            .and_modify(|counter| counter.value += 1)
            .or_insert(Counter {
                name: name.to_string(),
                labels,
                value: 1,
            });
    }

    pub fn render_prometheus(&self) -> String {
        let counters = self.counters.lock().expect("metrics mutex poisoned");
        let mut values = counters.values().cloned().collect::<Vec<_>>();
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

fn counter_key(name: &str, labels: &[(String, String)]) -> String {
    let mut key = name.to_string();
    for (label, value) in labels {
        key.push('|');
        key.push_str(label);
        key.push('=');
        key.push_str(value);
    }
    key
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
}
