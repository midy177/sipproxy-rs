use crate::config::{ProxyConfig, RouteConfig};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct SelectedRoute {
    pub name: String,
    pub upstream_group: String,
}

#[derive(Debug, Clone)]
pub struct RouteTable {
    routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    name: String,
    listener: Option<String>,
    domain: Option<String>,
    prefix: Option<String>,
    upstream_group: String,
}

impl RouteTable {
    pub fn new(config: &ProxyConfig) -> Result<Self> {
        let routes = config
            .routes
            .iter()
            .map(RouteEntry::try_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { routes })
    }

    pub fn select(&self, listener_key: &str, uri: &str) -> Option<SelectedRoute> {
        self.routes
            .iter()
            .filter(|route| route.matches(listener_key, uri))
            .max_by_key(|route| route.specificity())
            .map(|route| SelectedRoute {
                name: route.name.clone(),
                upstream_group: route.upstream_group.clone(),
            })
    }
}

impl RouteEntry {
    fn matches(&self, listener_key: &str, uri: &str) -> bool {
        let listener_match = self
            .listener
            .as_ref()
            .is_none_or(|listener| listener == listener_key);
        let domain_match = self
            .domain
            .as_ref()
            .is_none_or(|domain| uri.contains(domain));
        let prefix_match = self
            .prefix
            .as_ref()
            .is_none_or(|prefix| uri.starts_with(prefix));
        listener_match && domain_match && prefix_match
    }

    fn specificity(&self) -> usize {
        usize::from(self.listener.is_some())
            + usize::from(self.domain.is_some())
            + usize::from(self.prefix.is_some())
    }
}

impl TryFrom<&RouteConfig> for RouteEntry {
    type Error = anyhow::Error;

    fn try_from(value: &RouteConfig) -> Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            listener: value.listener.clone(),
            domain: value.domain.clone(),
            prefix: value.prefix.clone(),
            upstream_group: value.upstream_group.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_selection_prefers_matching_domain_and_prefix() {
        let table = RouteTable::new(&ProxyConfig {
            record_route: true,
            socket: Default::default(),
            metrics: Default::default(),
            affinity: Default::default(),
            routes: vec![RouteConfig {
                name: "tenant-a".to_string(),
                listener: Some("udp/127.0.0.1:5060".to_string()),
                domain: Some("tenant-a.example.com".to_string()),
                prefix: Some("sip:1".to_string()),
                upstream_group: "tenant-a".to_string(),
            }],
            listeners: vec![],
            upstream_groups: vec![],
        })
        .unwrap();

        let selected = table
            .select("udp/127.0.0.1:5060", "sip:100@tenant-a.example.com")
            .unwrap();
        assert_eq!(selected.name, "tenant-a");
        assert_eq!(selected.upstream_group, "tenant-a");

        assert!(
            table
                .select("udp/127.0.0.1:5080", "sip:100@tenant-a.example.com")
                .is_none()
        );
    }
}
