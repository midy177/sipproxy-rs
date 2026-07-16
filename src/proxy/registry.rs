use crate::sip::SipMessage;
use anyhow::{Context, Result};
use rsipstack::sip::prelude::HeadersExt;
use std::time::Duration;

pub fn extract_aor(message: &SipMessage) -> Result<String> {
    let request = message
        .as_request()
        .context("REGISTER parsing requires a SIP request")?;
    let uri = match request.to_header() {
        Ok(to) => rsipstack::sip::typed::To::parse(to.value())?.uri,
        Err(_) => rsipstack::sip::typed::From::parse(request.from_header()?.value())?.uri,
    };
    Ok(uri.to_string())
}

pub fn extract_contact(message: &SipMessage) -> Result<Option<String>> {
    let request = message
        .as_request()
        .context("REGISTER parsing requires a SIP request")?;
    let contact = request
        .typed_contact_headers()?
        .into_iter()
        .find(|contact| contact.to_string() != "*");
    Ok(contact.map(|contact| contact.uri.to_string()))
}

pub fn extract_expires(message: &SipMessage) -> Duration {
    let Some(request) = message.as_request() else {
        return Duration::from_secs(3600);
    };
    if let Ok(contacts) = request.typed_contact_headers()
        && let Some(seconds) = contacts.into_iter().find_map(|contact| contact.expires())
    {
        return Duration::from_secs(u64::from(seconds));
    }
    if let Some(expires) = request.expires_header()
        && let Ok(seconds) = expires.value().trim().parse::<u64>()
    {
        return Duration::from_secs(seconds);
    }
    Duration::from_secs(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_register_aor_contact_and_expires() {
        let msg = SipMessage::parse(
            b"REGISTER sip:example.com SIP/2.0\r\n\
To: <sip:100@example.com>\r\n\
From: <sip:100@example.com>;tag=abc\r\n\
Contact: <sip:100@127.0.0.1:5062>;expires=120\r\n\
Call-ID: c1\r\n\
CSeq: 1 REGISTER\r\n\r\n",
        )
        .unwrap();

        assert_eq!(extract_aor(&msg).unwrap(), "sip:100@example.com");
        assert_eq!(
            extract_contact(&msg).unwrap().unwrap(),
            "sip:100@127.0.0.1:5062"
        );
        assert_eq!(extract_expires(&msg), Duration::from_secs(120));
    }
}
