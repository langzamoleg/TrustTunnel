use std::io;
use std::io::ErrorKind;
use crate::net_utils;
use crate::settings::{ListenProtocolSettings, Settings};


#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum TunnelProtocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum PingProtocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum ServiceMessengerProtocol {
    Http1,
    Http3,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Protocol {
    Tunnel(TunnelProtocol),
    Ping(PingProtocol),
    ServiceMessenger(ServiceMessengerProtocol),
}

impl Protocol {
    pub fn as_alpn(&self) -> &'static str {
        match self {
            Protocol::Tunnel(TunnelProtocol::Http1) => net_utils::HTTP1_ALPN,
            Protocol::Tunnel(TunnelProtocol::Http2) => net_utils::HTTP2_ALPN,
            Protocol::Tunnel(TunnelProtocol::Http3) => net_utils::HTTP3_ALPN,
            Protocol::Ping(PingProtocol::Http1) => net_utils::HTTP1_ALPN,
            Protocol::Ping(PingProtocol::Http2) => net_utils::HTTP2_ALPN,
            Protocol::Ping(PingProtocol::Http3) => net_utils::HTTP3_ALPN,
            Protocol::ServiceMessenger(ServiceMessengerProtocol::Http1) => net_utils::HTTP1_ALPN,
            Protocol::ServiceMessenger(ServiceMessengerProtocol::Http3) => net_utils::HTTP3_ALPN,
        }
    }
}

impl TunnelProtocol {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Http1 => "HTTP1",
            Self::Http2 => "HTTP2",
            Self::Http3 => "HTTP3",
        }
    }
}

pub(crate) fn select(settings: &Settings, alpn: Option<&str>, sni: &str) -> io::Result<Protocol> {
    let proto = if Some(sni) == settings.service_messenger_tls_host_info.as_ref().map(|i| i.hostname.as_str()) {
        match alpn.unwrap_or_default() {
            net_utils::HTTP1_ALPN => Ok(Protocol::ServiceMessenger(ServiceMessengerProtocol::Http1)),
            net_utils::HTTP3_ALPN => Ok(Protocol::ServiceMessenger(ServiceMessengerProtocol::Http3)),
            _ => Err(io::Error::new(
                ErrorKind::Other, format!("Unexpected ALPN on service messenger connection {:?}", alpn)
            )),
        }
    } else if Some(sni) == settings.ping_tls_host_info.as_ref().map(|i| i.hostname.as_str()) {
        match alpn.unwrap_or_default() {
            net_utils::HTTP1_ALPN => Ok(Protocol::Ping(PingProtocol::Http1)),
            net_utils::HTTP2_ALPN => Ok(Protocol::Ping(PingProtocol::Http2)),
            net_utils::HTTP3_ALPN => Ok(Protocol::Ping(PingProtocol::Http3)),
            _ => Err(io::Error::new(
                ErrorKind::Other, format!("Unexpected ALPN on pinging connection {:?}", alpn)
            )),
        }
    } else {
        match alpn.unwrap_or(net_utils::HTTP1_ALPN) {
            net_utils::HTTP1_ALPN => Ok(Protocol::Tunnel(TunnelProtocol::Http1)),
            net_utils::HTTP2_ALPN => Ok(Protocol::Tunnel(TunnelProtocol::Http2)),
            net_utils::HTTP3_ALPN => Ok(Protocol::Tunnel(TunnelProtocol::Http3)),
            _ => Err(io::Error::new(
                ErrorKind::Other, format!("Unexpected ALPN on tunnel connection {:?}", alpn)
            )),
        }
    };

    match proto? {
        Protocol::Tunnel(x) => {
            if settings.listen_protocols.iter()
                .any(|i| matches!(
                    (i, &x),
                    (ListenProtocolSettings::Http1(_), TunnelProtocol::Http1)
                        | (ListenProtocolSettings::Http2(_), TunnelProtocol::Http2)
                        | (ListenProtocolSettings::Quic(_), TunnelProtocol::Http3)
                ))
            {
                Ok(Protocol::Tunnel(x))
            } else {
                Err(io::Error::new(
                    ErrorKind::Other, format!("Selected protocol is not being listened to: {:?}", x)
                ))
            }
        }
        x => Ok(x),
    }
}
