use crate::config::{ProxyConfig, RouteConfig};
use anyhow::Result;
use rsipstack::sip::Uri;
use std::collections::HashMap;

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
        let listener_aliases = listener_route_aliases(config);
        let routes = config
            .routes
            .iter()
            .flat_map(|route| expand_route_listeners(route, &listener_aliases))
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

fn listener_route_aliases(config: &ProxyConfig) -> HashMap<String, Vec<String>> {
    let mut aliases = HashMap::new();
    for listener in &config.listeners {
        let concrete_keys = listener
            .concrete_listeners()
            .into_iter()
            .map(|listener| listener.key())
            .collect::<Vec<_>>();
        aliases.insert(listener.key(), concrete_keys.clone());
        for key in concrete_keys {
            aliases.insert(key.clone(), vec![key]);
        }
    }
    aliases
}

fn expand_route_listeners(
    route: &RouteConfig,
    listener_aliases: &HashMap<String, Vec<String>>,
) -> Vec<Result<RouteEntry>> {
    match &route.listener {
        Some(listener) => listener_aliases
            .get(listener)
            .cloned()
            .unwrap_or_else(|| vec![listener.clone()])
            .into_iter()
            .map(|listener| RouteEntry::try_from_with_listener(route, Some(listener)))
            .collect(),
        None => vec![RouteEntry::try_from_with_listener(route, None)],
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
            .is_none_or(|domain| uri_host_matches(uri, domain));
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

fn uri_host_matches(uri: &str, domain: &str) -> bool {
    let Ok(uri) = uri.parse::<Uri>() else {
        return false;
    };
    uri.host().to_string().eq_ignore_ascii_case(domain)
}

impl TryFrom<&RouteConfig> for RouteEntry {
    type Error = anyhow::Error;

    fn try_from(value: &RouteConfig) -> Result<Self> {
        Self::try_from_with_listener(value, value.listener.clone())
    }
}

impl RouteEntry {
    fn try_from_with_listener(value: &RouteConfig, listener: Option<String>) -> Result<Self> {
        Ok(Self {
            name: value.name.clone(),
            listener,
            domain: value.domain.clone(),
            prefix: value.prefix.clone(),
            upstream_group: value.upstream_group.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyListenerConfig, SipTransport};

    #[test]
    fn route_selection_prefers_matching_domain_and_prefix() {
        let table = RouteTable::new(&ProxyConfig {
            record_route: true,
            register_routing: None,
            rewrite_register_contact: false,
            udp_client_transaction_cache_entries: 65_536,
            socket: Default::default(),
            metrics: Default::default(),
            affinity: Default::default(),
            security: Default::default(),
            routes: vec![RouteConfig {
                name: "tenant-a".to_string(),
                listener: Some("udp/127.0.0.1:5060".to_string()),
                domain: Some("tenant-a.example.com".to_string()),
                prefix: Some("sip:1".to_string()),
                upstream_group: "tenant-a".to_string(),
            }],
            listeners: vec![],
            upstream_source_cidrs: vec![],
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
        assert!(
            table
                .select(
                    "udp/127.0.0.1:5060",
                    "sip:100@tenant-a.example.com.evil.test"
                )
                .is_none()
        );
        assert!(
            table
                .select("udp/127.0.0.1:5060", "sip:tenant-a.example.com@evil.test")
                .is_none()
        );
    }

    #[test]
    fn route_listener_alias_expands_tcp_udp_listener_key() {
        let table = RouteTable::new(&ProxyConfig {
            record_route: true,
            register_routing: None,
            rewrite_register_contact: false,
            udp_client_transaction_cache_entries: 65_536,
            socket: Default::default(),
            metrics: Default::default(),
            affinity: Default::default(),
            security: Default::default(),
            routes: vec![RouteConfig {
                name: "tenant-a".to_string(),
                listener: Some("tcp_udp/127.0.0.1:5060".to_string()),
                domain: None,
                prefix: None,
                upstream_group: "tenant-a".to_string(),
            }],
            listeners: vec![ProxyListenerConfig {
                bind: "127.0.0.1:5060".to_string(),
                transport: SipTransport::TcpUdp,
                upstream_group: "default".to_string(),
                security: None,
            }],
            upstream_source_cidrs: vec![],
            upstream_groups: vec![],
        })
        .unwrap();

        assert_eq!(
            table
                .select("udp/127.0.0.1:5060", "sip:100@example.com")
                .unwrap()
                .upstream_group,
            "tenant-a"
        );
        assert_eq!(
            table
                .select("tcp/127.0.0.1:5060", "sip:100@example.com")
                .unwrap()
                .upstream_group,
            "tenant-a"
        );
    }
}
