use anyhow::{Context, Result};
use rsipstack::sip::headers::{Header, Headers, untyped::Path as UntypedPath};
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{
    Auth, ContentLength, HasHeaders, HostWithPort, MaxForwards, Method, Param, Request, Response,
    SipMessage as RsipMessage, StatusCode, Transport, Uri, Version,
    headers::{CallId, UserAgent},
    param::{Branch, Tag},
    typed::{
        CSeq, Contact as TypedContact, From as FromHeader, RecordRoute, Route as TypedRoute,
        To as ToHeader, Via,
    },
    uri::{Host, Received},
};
use std::net::{IpAddr, SocketAddr};

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipStartLine {
    Request {
        method: String,
        uri: String,
        version: String,
    },
    Response {
        version: String,
        code: u16,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipMessage {
    inner: RsipMessage,
    pub start_line: SipStartLine,
}

impl SipMessage {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let inner = RsipMessage::try_from(bytes).context("failed to parse SIP message")?;
        Ok(Self::from_inner(inner))
    }

    pub fn method(&self) -> Option<&str> {
        match &self.inner {
            RsipMessage::Request(request) => Some(method_name(&request.method)),
            RsipMessage::Response(_) => None,
        }
    }

    pub fn request_uri(&self) -> Option<String> {
        match &self.inner {
            RsipMessage::Request(request) => Some(request.uri.to_string()),
            RsipMessage::Response(_) => None,
        }
    }

    pub fn as_request(&self) -> Option<&Request> {
        match &self.inner {
            RsipMessage::Request(request) => Some(request),
            RsipMessage::Response(_) => None,
        }
    }

    pub fn is_response(&self) -> bool {
        matches!(self.inner, RsipMessage::Response(_))
    }

    pub fn top_via_branch(&self) -> Result<Option<String>> {
        Ok(self
            .inner
            .transaction_id()
            .context("failed to parse top Via branch")?
            .map(|branch| branch.to_string()))
    }

    pub fn pop_top_via(&mut self) -> Result<Option<String>> {
        let Some((index, value)) =
            self.inner
                .headers()
                .iter()
                .enumerate()
                .find_map(|(index, header)| match header {
                    Header::Via(via) => Some((index, via.value().to_string())),
                    Header::Other(name, value) if name.eq_ignore_ascii_case("Via") => {
                        Some((index, value.to_string()))
                    }
                    _ => None,
                })
        else {
            return Ok(None);
        };

        let (top, rest) = split_first_header_value(&value).context("failed to split top Via")?;
        let headers = self.inner.headers_mut();
        match rest {
            Some(rest) if !rest.trim().is_empty() => match &mut headers.0[index] {
                Header::Via(via) => via.replace(rest.trim().to_string()),
                Header::Other(_, value) => *value = rest.trim().to_string(),
                _ => unreachable!("Via header index changed while popping top Via"),
            },
            _ => {
                headers.0.remove(index);
            }
        }
        Ok(Some(top.trim().to_string()))
    }

    pub fn pop_top_header_value(&mut self, name: &str) -> Result<Option<String>> {
        let Some((index, value)) = self
            .inner
            .headers()
            .iter()
            .enumerate()
            .find(|(_, header)| header.name().eq_ignore_ascii_case(name))
            .map(|(index, header)| (index, header.value().to_string()))
        else {
            return Ok(None);
        };

        let (top, rest) = split_first_header_value(&value)
            .with_context(|| format!("failed to split top {name}"))?;
        let headers = self.inner.headers_mut();
        match rest {
            Some(rest) if !rest.trim().is_empty() => {
                headers.0[index] = Header::Other(name.to_string(), rest.trim().to_string());
            }
            _ => {
                headers.0.remove(index);
            }
        }
        Ok(Some(top.trim().to_string()))
    }

    pub fn top_header_value(&self, name: &str) -> Result<Option<String>> {
        let Some(value) = self
            .inner
            .headers()
            .iter()
            .find(|header| header.name().eq_ignore_ascii_case(name))
            .map(|header| header.value().to_string())
        else {
            return Ok(None);
        };

        let (top, _) = split_first_header_value(&value)
            .with_context(|| format!("failed to split top {name}"))?;
        Ok(Some(top.trim().to_string()))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.inner
            .headers()
            .iter()
            .find(|header| header.name().eq_ignore_ascii_case(name))
            .map(Header::value)
    }

    pub fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.inner
            .headers()
            .iter()
            .filter(move |header| header.name().eq_ignore_ascii_case(name))
            .map(Header::value)
    }

    pub fn remove_headers(&mut self, name: &str) {
        self.inner
            .headers_mut()
            .retain(|header| !header.name().eq_ignore_ascii_case(name));
    }

    pub fn prepend_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.inner
            .headers_mut()
            .push_front(Header::Other(name.into(), value.into()));
    }

    pub fn prepend_via(
        &mut self,
        transport: Transport,
        sent_by: &str,
        branch: impl Into<String>,
    ) -> Result<()> {
        let sent_by = HostWithPort::try_from(sent_by).context("invalid Via sent-by")?;
        let via = Via {
            version: Version::V2,
            transport,
            uri: sent_by.into(),
            params: vec![
                Param::Branch(Branch::new(branch.into())),
                Param::Rport(None),
            ],
        };
        self.inner.headers_mut().push_front(via.into());
        Ok(())
    }

    pub fn prepend_record_route(&mut self, addr: &str) -> Result<()> {
        let uri = format!("sip:{addr};lr")
            .parse::<Uri>()
            .context("invalid Record-Route URI")?;
        self.inner
            .headers_mut()
            .push_front(RecordRoute::from(uri).into());
        Ok(())
    }

    pub fn prepend_path(&mut self, addr: &str) -> Result<()> {
        let route = TypedRoute::parse(&format!("<sip:{addr};lr>")).context("invalid Path URI")?;
        self.inner
            .headers_mut()
            .push_front(Header::Path(UntypedPath::new(route.to_string())));
        Ok(())
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(header) = self
            .inner
            .headers_mut()
            .iter_mut()
            .find(|header| header.name().eq_ignore_ascii_case(&name))
        {
            *header = Header::Other(name, value);
        } else {
            self.inner.headers_mut().push(Header::Other(name, value));
        }
    }

    pub fn apply_top_via_received_rport(&mut self, peer: SocketAddr) -> Result<()> {
        let Some((index, value)) = self
            .inner
            .headers()
            .iter()
            .enumerate()
            .find(|(_, header)| header.name().eq_ignore_ascii_case("Via"))
            .map(|(index, header)| (index, header.value().to_string()))
        else {
            return Ok(());
        };

        let (top, rest) = split_first_header_value(&value).context("failed to split top Via")?;
        let top = top.trim();
        let rewritten = rewrite_via_received_rport_typed(top, peer)
            .unwrap_or_else(|| rewrite_via_received_rport(top, peer));
        match rest {
            Some(rest) if !rest.trim().is_empty() => {
                self.inner.headers_mut().0[index] =
                    Header::Other("Via".to_string(), format!("{rewritten}, {}", rest.trim()));
            }
            _ => {
                self.inner.headers_mut().0[index] =
                    Header::Via(rsipstack::sip::headers::untyped::Via::new(rewritten));
            }
        }
        Ok(())
    }

    pub fn rewrite_contact_host(&mut self, sent_by: &str) -> Result<Vec<(String, String)>> {
        self.rewrite_contact_host_with_user(sent_by, |_, user| user.to_string())
    }

    pub fn rewrite_contact_host_with_user<F>(
        &mut self,
        sent_by: &str,
        mut rewrite_user: F,
    ) -> Result<Vec<(String, String)>>
    where
        F: FnMut(&str, &str) -> String,
    {
        let host_with_port =
            HostWithPort::try_from(sent_by).context("invalid Contact rewrite host")?;
        let mut rewritten = Vec::new();
        for header in self
            .inner
            .headers_mut()
            .iter_mut()
            .filter(|header| header.name().eq_ignore_ascii_case("Contact"))
        {
            let contacts = TypedContact::parse_header_list(header.value())
                .context("failed to parse Contact header")?;
            let rendered = contacts
                .into_iter()
                .map(|mut contact| {
                    if contact.to_string() != "*" {
                        let original = contact.uri.to_string();
                        contact.uri.host_with_port = host_with_port.clone();
                        contact.uri.params.retain(|param| *param != Param::Ob);
                        let original_user = contact.uri.user().unwrap_or_default().to_string();
                        let rewritten_user = rewrite_user(&original, &original_user);
                        if !rewritten_user.is_empty() {
                            if let Some(auth) = contact.uri.auth.as_mut() {
                                auth.user = rewritten_user;
                            } else {
                                contact.uri.auth = Some(Auth::from(rewritten_user));
                            }
                        }
                        rewritten.push((original, contact.uri.to_string()));
                    }
                    contact.to_string()
                })
                .collect::<Vec<_>>()
                .join(", ");
            *header = Header::Other("Contact".to_string(), rendered);
        }
        Ok(rewritten)
    }

    pub fn max_forwards(&self) -> Result<Option<u32>> {
        let value = match &self.inner {
            RsipMessage::Request(request) => request.max_forwards_header().ok(),
            RsipMessage::Response(response) => response.max_forwards_header().ok(),
        };
        let Some(value) = value else {
            return Ok(None);
        };
        value
            .value()
            .trim()
            .parse::<u32>()
            .map(Some)
            .context("Max-Forwards must be an unsigned integer")
    }

    pub fn set_max_forwards(&mut self, hops: u32) {
        if let Some(header) = self
            .inner
            .headers_mut()
            .iter_mut()
            .find(|header| header.name().eq_ignore_ascii_case("Max-Forwards"))
        {
            *header = Header::MaxForwards(MaxForwards::from(hops));
        } else {
            self.inner
                .headers_mut()
                .push(Header::MaxForwards(MaxForwards::from(hops)));
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn response_like(request: &Self, code: u16, reason: &str) -> Self {
        let mut headers = Headers::default();
        for header in request.inner.headers().iter() {
            match header {
                Header::Via(_)
                | Header::From(_)
                | Header::To(_)
                | Header::CallId(_)
                | Header::CSeq(_) => {
                    headers.push(header.clone());
                }
                _ => {}
            }
        }
        headers.push(Header::ContentLength(ContentLength::from(0)));

        let status_code =
            StatusCode::try_from((code, reason)).unwrap_or_else(|_| StatusCode::from(code));
        Self::from_inner(RsipMessage::Response(Response {
            status_code,
            version: Version::V2,
            headers,
            body: Vec::new(),
        }))
    }

    pub fn options_request(
        uri: &str,
        transport: Transport,
        sent_by: SocketAddr,
        branch: impl Into<String>,
        tag: impl Into<String>,
        call_id: impl Into<String>,
        cseq: u32,
    ) -> Result<Self> {
        let uri = uri.parse::<Uri>().context("invalid OPTIONS request URI")?;
        let from_uri = "sip:healthcheck@localhost"
            .parse::<Uri>()
            .context("invalid health-check From URI")?;
        let via = Via {
            version: Version::V2,
            transport,
            uri: HostWithPort::from(sent_by).into(),
            params: vec![
                Param::Branch(Branch::new(branch.into())),
                Param::Rport(None),
            ],
        };
        let from = FromHeader {
            display_name: None,
            uri: from_uri,
            params: vec![Param::Tag(Tag::new(tag.into()))],
        };
        let to = ToHeader {
            display_name: None,
            uri: uri.clone(),
            params: Vec::new(),
        };
        let request = Request {
            method: Method::Options,
            uri,
            version: Version::V2,
            headers: Headers::from(vec![
                via.into(),
                from.into(),
                to.into(),
                CallId::new(call_id).into(),
                CSeq {
                    seq: cseq,
                    method: Method::Options,
                }
                .into(),
                MaxForwards::from(70u32).into(),
                Header::UserAgent(UserAgent::new(USER_AGENT)),
                ContentLength::from(0u32).into(),
            ]),
            body: Vec::new(),
        };
        Ok(Self::from_inner(RsipMessage::Request(request)))
    }

    fn from_inner(inner: RsipMessage) -> Self {
        let start_line = match &inner {
            RsipMessage::Request(request) => SipStartLine::Request {
                method: method_name(&request.method).to_string(),
                uri: request.uri.to_string(),
                version: request.version.to_string(),
            },
            RsipMessage::Response(response) => SipStartLine::Response {
                version: response.version.to_string(),
                code: response.status_code.code(),
                reason: response.status_code.text().to_string(),
            },
        };
        Self { inner, start_line }
    }
}

fn split_first_header_value(value: &str) -> Result<(&str, Option<&str>)> {
    if value.is_empty() {
        return Ok((value, None));
    }

    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth = 0usize;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => angle_depth += 1,
            '>' if !in_quotes => angle_depth = angle_depth.saturating_sub(1),
            ',' if !in_quotes && angle_depth == 0 => {
                return Ok((&value[..index], Some(&value[index + 1..])));
            }
            _ => {}
        }
    }

    if in_quotes {
        anyhow::bail!("unclosed quoted header value");
    }
    Ok((value, None))
}

fn rewrite_via_received_rport(value: &str, peer: SocketAddr) -> String {
    let mut parts = value.split(';');
    let sent_protocol = parts.next().unwrap_or_default().trim();
    let mut rendered = sent_protocol.to_string();
    let mut has_received = false;
    let should_add_received = via_sent_by_ip(sent_protocol).is_none_or(|ip| ip != peer.ip());
    let peer_ip = peer.ip().to_string();
    let peer_port = peer.port();

    for param in parts {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let (name, _) = param.split_once('=').unwrap_or((param, ""));
        let name = name.trim();
        if name.eq_ignore_ascii_case("received") {
            has_received = true;
            rendered.push_str(";received=");
            rendered.push_str(&peer_ip);
        } else if name.eq_ignore_ascii_case("rport") {
            rendered.push_str(";rport=");
            rendered.push_str(&peer_port.to_string());
        } else {
            rendered.push(';');
            rendered.push_str(param);
        }
    }

    if !has_received && should_add_received {
        rendered.push_str(";received=");
        rendered.push_str(&peer_ip);
    }
    rendered
}

fn rewrite_via_received_rport_typed(value: &str, peer: SocketAddr) -> Option<String> {
    let mut via = Via::parse(value).ok()?.with_rport(Some(peer.port()));
    let should_add_received = match &via.sent_by().host {
        Host::IpAddr(ip) => *ip != peer.ip(),
        Host::Domain(_) => true,
    };
    if should_add_received {
        via = via.with_received(Received::new(peer.ip().to_string()));
    }
    Some(via.to_string())
}

fn via_sent_by_ip(sent_protocol: &str) -> Option<IpAddr> {
    let sent_by = sent_protocol.split_whitespace().last()?;
    if let Some((host, _)) = sent_by
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        return host.parse().ok();
    }
    let host = sent_by.split_once(':').map_or(sent_by, |(host, _)| host);
    host.parse().ok()
}

fn method_name(method: &Method) -> &str {
    match method {
        Method::Invite => "INVITE",
        Method::Ack => "ACK",
        Method::Bye => "BYE",
        Method::Cancel => "CANCEL",
        Method::Register => "REGISTER",
        Method::Options => "OPTIONS",
        Method::Subscribe => "SUBSCRIBE",
        Method::Notify => "NOTIFY",
        Method::Refer => "REFER",
        Method::Message => "MESSAGE",
        Method::Update => "UPDATE",
        Method::Info => "INFO",
        Method::PRack => "PRACK",
        Method::Publish => "PUBLISH",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_request() {
        let msg = SipMessage::parse(
            b"INVITE sip:100@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\r\n\
From: <sip:200@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(msg.method(), Some("INVITE"));
        assert_eq!(msg.request_uri().as_deref(), Some("sip:100@example.com"));
        assert_eq!(msg.header("call-id"), Some("c1"));
        assert!(
            String::from_utf8(msg.to_bytes())
                .unwrap()
                .contains("INVITE")
        );
    }

    #[test]
    fn builds_response_like_request() {
        let req = SipMessage::parse(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1\r\n\
From: <sip:200@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 OPTIONS\r\n\r\n",
        )
        .unwrap();
        let resp = SipMessage::response_like(&req, 200, "OK");
        assert!(
            String::from_utf8(resp.to_bytes())
                .unwrap()
                .starts_with("SIP/2.0 200 OK")
        );
    }

    #[test]
    fn builds_typed_options_health_request() {
        let request = SipMessage::options_request(
            "sip:healthcheck@example.com",
            Transport::Udp,
            "127.0.0.1:5099".parse().unwrap(),
            "z9hG4bK-health-1",
            "health-tag-1",
            "health-call-1@sigproxy",
            42,
        )
        .unwrap();

        assert_eq!(request.method(), Some("OPTIONS"));
        assert_eq!(
            request.request_uri().as_deref(),
            Some("sip:healthcheck@example.com")
        );
        assert_eq!(
            request.top_via_branch().unwrap().as_deref(),
            Some("z9hG4bK-health-1")
        );
        assert_eq!(request.max_forwards().unwrap(), Some(70));
        let wire = String::from_utf8(request.to_bytes()).unwrap();
        assert!(wire.contains("Via: SIP/2.0/UDP 127.0.0.1:5099;branch=z9hG4bK-health-1;rport"));
        assert!(wire.contains("CSeq: 42 OPTIONS"));
        assert!(wire.contains("User-Agent: sigproxy-rs/0.1.0"));
        assert!(wire.contains("Content-Length: 0"));
    }

    #[test]
    fn prepends_path_with_route_syntax_validation() {
        let mut request = SipMessage::parse(
            b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:100@example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        request.prepend_path("127.0.0.1:5060").unwrap();
        let wire = String::from_utf8(request.to_bytes()).unwrap();

        assert!(wire.contains("Path: <sip:127.0.0.1:5060;lr>"));
    }

    #[test]
    fn response_like_copies_standard_header_variants() {
        let req = SipMessage::parse(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy\r\n\
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-client\r\n\
From: <sip:200@example.com>;tag=a\r\n\
To: <sip:example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        let resp =
            String::from_utf8(SipMessage::response_like(&req, 200, "OK").to_bytes()).unwrap();

        assert!(resp.contains("Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy"));
        assert!(resp.contains("Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-client"));
        assert!(resp.contains("Content-Length: 0"));
    }

    #[test]
    fn fills_top_via_received_and_rport_for_nat_peer() {
        let mut resp = SipMessage::parse(
            b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP 100.105.80.106:56433;branch=z9hG4bK-client;rport\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: c1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        resp.apply_top_via_received_rport("112.48.56.8:60834".parse().unwrap())
            .unwrap();
        let wire = String::from_utf8(resp.to_bytes()).unwrap();

        assert!(wire.contains(
            "Via: SIP/2.0/UDP 100.105.80.106:56433;branch=z9hG4bK-client;rport=60834;received=112.48.56.8"
        ));
    }

    #[test]
    fn leaves_received_out_when_sent_by_matches_peer() {
        let mut resp = SipMessage::parse(
            b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-client;rport\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: c1\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        resp.apply_top_via_received_rport("127.0.0.1:5061".parse().unwrap())
            .unwrap();
        let wire = String::from_utf8(resp.to_bytes()).unwrap();

        assert!(wire.contains("rport=5061"));
        assert!(!wire.contains("received="));
    }

    #[test]
    fn pops_only_top_via_value() {
        let mut resp = SipMessage::parse(
            b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy, SIP/2.0/UDP client.example.com;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>;tag=b\r\n\
Call-ID: c1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            resp.top_via_branch().unwrap().as_deref(),
            Some("z9hG4bK-proxy")
        );
        assert_eq!(
            resp.pop_top_via().unwrap().as_deref(),
            Some("SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy")
        );
        assert_eq!(
            resp.top_via_branch().unwrap().as_deref(),
            Some("z9hG4bK-client")
        );
    }

    #[test]
    fn header_list_split_ignores_commas_inside_name_addr() {
        let mut request = SipMessage::parse(
            b"INVITE sip:100@example.com SIP/2.0\r\n\
Route: <sip:proxy.example.com;lr?X-Trace=a,b>, <sip:edge.example.com;lr>\r\n\
Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK-client\r\n\
From: <sip:100@example.com>;tag=a\r\n\
To: <sip:200@example.com>\r\n\
Call-ID: c1\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(
            request.top_header_value("Route").unwrap().as_deref(),
            Some("<sip:proxy.example.com;lr?X-Trace=a,b>")
        );
        assert_eq!(
            request.pop_top_header_value("Route").unwrap().as_deref(),
            Some("<sip:proxy.example.com;lr?X-Trace=a,b>")
        );
        assert_eq!(
            request.top_header_value("Route").unwrap().as_deref(),
            Some("<sip:edge.example.com;lr>")
        );
    }
}
