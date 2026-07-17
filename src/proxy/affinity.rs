use crate::config::{ProxyAffinityConfig, ProxyAffinityKey, SipTransport};
use crate::sip::SipMessage;
use anyhow::{Context, Result};
use rsipstack::sip::prelude::HeadersExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinityTarget {
    pub addr: SocketAddr,
    pub transport: SipTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AffinityKey(String);

impl AffinityKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinityStateSnapshot {
    pub bindings: Vec<AffinityBindingSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffinityBindingSnapshot {
    pub key: AffinityKey,
    pub target: AffinityTarget,
    pub expires_at_epoch_ms: u128,
}

#[derive(Debug)]
pub struct AffinityTable {
    config: ProxyAffinityConfig,
    bindings: Mutex<HashMap<AffinityKey, AffinityBinding>>,
}

#[derive(Debug, Clone, Copy)]
struct AffinityBinding {
    target: AffinityTarget,
    expires_at: Instant,
}

impl AffinityTable {
    pub fn new(config: ProxyAffinityConfig) -> Self {
        Self {
            config,
            bindings: Mutex::new(HashMap::new()),
        }
    }

    pub async fn lookup(&self, message: &SipMessage) -> Result<Option<AffinityTarget>> {
        if !self.config.enabled {
            return Ok(None);
        }
        let keys = affinity_keys(message, self.config.key)?;
        if keys.is_empty() {
            return Ok(None);
        }

        let mut bindings = self.bindings.lock().await;
        prune_affinity(&mut bindings, Instant::now());
        Ok(keys
            .iter()
            .find_map(|key| bindings.get(key).map(|binding| binding.target)))
    }

    pub async fn remember(&self, message: &SipMessage, target: AffinityTarget) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let keys = affinity_keys(message, self.config.key)?;
        if keys.is_empty() {
            return Ok(());
        }
        let expires_at = Instant::now() + Duration::from_secs(self.config.ttl_seconds);
        let mut bindings = self.bindings.lock().await;
        for key in keys {
            bindings.insert(key, AffinityBinding { target, expires_at });
        }
        Ok(())
    }

    pub async fn snapshot(&self) -> AffinityStateSnapshot {
        let now = Instant::now();
        let now_epoch_ms = now_epoch_ms();
        let mut bindings = self.bindings.lock().await;
        prune_affinity(&mut bindings, now);

        AffinityStateSnapshot {
            bindings: bindings
                .iter()
                .map(|(key, binding)| AffinityBindingSnapshot {
                    key: key.clone(),
                    target: binding.target,
                    expires_at_epoch_ms: now_epoch_ms
                        + binding
                            .expires_at
                            .saturating_duration_since(now)
                            .as_millis(),
                })
                .collect(),
        }
    }

    pub async fn install_snapshot(&self, snapshot: AffinityStateSnapshot) {
        let now_epoch_ms = now_epoch_ms();
        let now = Instant::now();
        let mut bindings = HashMap::new();
        for binding in snapshot.bindings {
            if binding.expires_at_epoch_ms <= now_epoch_ms {
                continue;
            }
            let ttl_ms = binding.expires_at_epoch_ms - now_epoch_ms;
            bindings.insert(
                binding.key,
                AffinityBinding {
                    target: binding.target,
                    expires_at: now + Duration::from_millis(ttl_ms as u64),
                },
            );
        }
        *self.bindings.lock().await = bindings;
    }

    pub async fn active_len(&self) -> usize {
        let mut bindings = self.bindings.lock().await;
        prune_affinity(&mut bindings, Instant::now());
        bindings.len()
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.active_len().await
    }
}

pub fn affinity_key(
    message: &SipMessage,
    strategy: ProxyAffinityKey,
) -> Result<Option<AffinityKey>> {
    Ok(affinity_keys(message, strategy)?.into_iter().next())
}

fn affinity_keys(message: &SipMessage, strategy: ProxyAffinityKey) -> Result<Vec<AffinityKey>> {
    let Some(request) = message.as_request() else {
        return Ok(Vec::new());
    };

    match strategy {
        ProxyAffinityKey::DialogId => {
            let mut keys = Vec::new();
            if let Some(dialog) = dialog_key(message)? {
                keys.push(dialog);
            }
            keys.push(call_id_key(message)?);
            Ok(keys)
        }
        ProxyAffinityKey::CallId => Ok(vec![call_id_key(message)?]),
        ProxyAffinityKey::RequestUri => {
            Ok(vec![AffinityKey(format!("request-uri:{}", request.uri))])
        }
    }
}

fn dialog_key(message: &SipMessage) -> Result<Option<AffinityKey>> {
    let request = message
        .as_request()
        .context("dialog affinity key requires a SIP request")?;
    let call_id = request.call_id_header()?.value().trim();
    let Ok(from_header) = request.from_header() else {
        return Ok(None);
    };
    let Ok(to_header) = request.to_header() else {
        return Ok(None);
    };
    let Ok(from) = rsipstack::sip::typed::From::parse(from_header.value()) else {
        return Ok(None);
    };
    let Ok(to) = rsipstack::sip::typed::To::parse(to_header.value()) else {
        return Ok(None);
    };
    let Some(from_tag) = from.tag() else {
        return Ok(None);
    };
    let Some(to_tag) = to.tag() else {
        return Ok(None);
    };

    let mut tags = [from_tag.to_string(), to_tag.to_string()];
    tags.sort();
    Ok(Some(AffinityKey(format!(
        "dialog-id:{call_id}:{}:{}",
        tags[0], tags[1]
    ))))
}

fn call_id_key(message: &SipMessage) -> Result<AffinityKey> {
    let request = message
        .as_request()
        .context("Call-ID affinity key requires a SIP request")?;
    Ok(AffinityKey(format!(
        "call-id:{}",
        request.call_id_header()?.value().trim()
    )))
}

fn prune_affinity(bindings: &mut HashMap<AffinityKey, AffinityBinding>, now: Instant) {
    bindings.retain(|_, binding| binding.expires_at > now);
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_key_is_direction_independent() {
        let invite_response_dialog = SipMessage::parse(
            b"ACK sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: c1\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        let reverse = SipMessage::parse(
            b"BYE sip:100@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK2\r\n\
From: <sip:200@example.com>;tag=b\r\n\
To: <sip:100@example.com>;tag=a\r\n\
Call-ID: c1\r\n\
CSeq: 2 BYE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            affinity_key(&invite_response_dialog, ProxyAffinityKey::DialogId)
                .unwrap()
                .unwrap(),
            affinity_key(&reverse, ProxyAffinityKey::DialogId)
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn affinity_table_expires_bindings() {
        let table = AffinityTable::new(ProxyAffinityConfig {
            enabled: true,
            key: ProxyAffinityKey::CallId,
            ttl_seconds: 1,
        });
        let request = SipMessage::parse(
            b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        let target = AffinityTarget {
            addr: "127.0.0.1:5080".parse().unwrap(),
            transport: SipTransport::Udp,
        };

        table.remember(&request, target).await.unwrap();
        assert_eq!(table.lookup(&request).await.unwrap(), Some(target));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(table.lookup(&request).await.unwrap(), None);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn affinity_snapshot_restores_bindings() {
        let config = ProxyAffinityConfig {
            enabled: true,
            key: ProxyAffinityKey::CallId,
            ttl_seconds: 60,
        };
        let source = AffinityTable::new(config.clone());
        let target_table = AffinityTable::new(config);
        let request = SipMessage::parse(
            b"MESSAGE sip:200@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK1\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 MESSAGE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();
        let target = AffinityTarget {
            addr: "127.0.0.1:5080".parse().unwrap(),
            transport: SipTransport::Udp,
        };

        source.remember(&request, target).await.unwrap();
        target_table.install_snapshot(source.snapshot().await).await;

        assert_eq!(target_table.lookup(&request).await.unwrap(), Some(target));
    }
}
