//! Transport-specific response framing happens only after the shared service finishes.
use super::{
    browser, keepalive,
    transport::{self, Tls},
};
use serde_json::Value;
use std::sync::mpsc;

pub(super) enum Reply {
    Native(Tls),
    Browser(browser::Response),
}
impl Reply {
    pub(super) fn finish(
        self,
        value: Value,
        idle: &mpsc::SyncSender<Tls>,
        permits: Vec<super::admission::Permit>,
    ) {
        match self {
            Self::Native(mut stream) => {
                // Charge the in-flight request through the write. Only after
                // releasing it may the socket admit another authenticated frame.
                let written = transport::reply(&mut stream, value);
                drop(permits);
                keepalive::park(idle, stream, written);
            }
            Self::Browser(response) => {
                response.send(200, value);
                drop(permits);
            }
        }
    }
    pub(super) fn reject(self, value: Value) {
        match self {
            Self::Native(mut stream) => {
                transport::reply(&mut stream, value);
            }
            // Protocol errors use the native envelope and HTTP 200, so the
            // existing wallet core sees exact same error/recovery semantics.
            Self::Browser(response) => response.send(200, value),
        }
    }
}
