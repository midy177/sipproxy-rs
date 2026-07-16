use anyhow::{Context, Result};
use rsipstack::sip::headers::{Header, Headers};
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{
    ContentLength, HasHeaders, MaxForwards, Method, Request, Response, SipMessage as RsipMessage,
    StatusCode, Version,
};

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
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => return Ok((&value[..index], Some(&value[index + 1..]))),
            _ => {}
        }
    }

    if in_quotes {
        anyhow::bail!("unclosed quoted header value");
    }
    Ok((value, None))
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
}
