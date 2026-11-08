// Copyright (c) 2026 Adequate Systems HK Limited
// Licensed under the Mochimo Cryptocurrency Engine License Agreement 1.0; see LICENSE.md.

//! The HTTP transport: `ureq` over a base URL, with failures mapped to
//! [`TransportKind`] without their messages.
//!
//! * **No redirects.** A redirect would re-POST a signed transaction to a
//!   host the caller did not name.
//! * **Non-200 statuses are errors.** The middleware reports its own failures
//!   as 200s with an error object; any other status is
//!   [`Error::HttpStatus`] and the body is not read.
//! * **Size limits both ways.** A request over [`MAX_REQUEST_BYTES`] is
//!   refused before connecting; a response is read up to the per-path cap
//!   from [`max_response_bytes`].
//! * **`https://` needs the `mesh-https` feature.** Without a TLS provider an
//!   `https://` base is refused at construction.
//!
//! The loopback tests in `tests/mesh_http.rs` use plain HTTP; TLS is
//! exercised by `examples/mesh_probe.rs` against a live node.

use core::fmt;
use std::time::Duration;

use crate::error::{Error, Result, TransportKind};

use super::{max_response_bytes, Transport, MAX_REQUEST_BYTES};

/// [`Transport`] over `ureq`.
pub struct UreqTransport {
    base: String,
    agent: ureq::Agent,
}

impl UreqTransport {
    /// The connect timeout [`UreqTransport::new`] uses.
    pub const DEFAULT_CONNECT: Duration = Duration::from_secs(10);
    /// The whole-request timeout [`UreqTransport::new`] uses.
    pub const DEFAULT_GLOBAL: Duration = Duration::from_secs(30);

    /// A transport for `base` (`http://host[:port]` or `https://host`, with
    /// no path, query or fragment; one trailing slash is stripped), using the
    /// default timeouts.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`] with [`TransportKind::Protocol`] for a malformed
    /// base, or [`TransportKind::Tls`] for `https://` without `mesh-https`.
    pub fn new(base: &str) -> Result<UreqTransport> {
        Self::with_timeouts(base, Self::DEFAULT_CONNECT, Self::DEFAULT_GLOBAL)
    }

    /// [`UreqTransport::new`] with explicit connect and whole-request
    /// timeouts; the loopback tests use short ones.
    pub fn with_timeouts(base: &str, connect: Duration, global: Duration) -> Result<UreqTransport> {
        let base = base.strip_suffix('/').unwrap_or(base);
        let secure = if let Some(rest) = base.strip_prefix("https://") {
            Self::check_authority(rest)?;
            true
        } else if let Some(rest) = base.strip_prefix("http://") {
            Self::check_authority(rest)?;
            false
        } else {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Protocol,
            });
        };
        if secure && !cfg!(feature = "mesh-https") {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Tls,
            });
        }
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(connect))
            .timeout_global(Some(global))
            // `mochimo-crypto/<version>` from the package metadata. The
            // crate name is used rather than the binary's, since library
            // users other than `tawara` share this transport.
            .user_agent(concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(UreqTransport {
            base: base.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        })
    }

    /// `host[:port]` and nothing else: no path, query, fragment or userinfo.
    fn check_authority(rest: &str) -> Result<()> {
        let bad = rest.is_empty() || rest.bytes().any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b' '));
        if bad {
            return Err(Error::Transport {
                op: "base url",
                kind: TransportKind::Protocol,
            });
        }
        Ok(())
    }

    /// The base URL this transport posts under.
    pub fn base(&self) -> &str {
        &self.base
    }
}

impl fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UreqTransport").field("base", &self.base).finish_non_exhaustive()
    }
}

/// The class of a `ureq` failure, without its message.
fn classify(e: &ureq::Error) -> TransportKind {
    match e {
        ureq::Error::Timeout(_) => TransportKind::Timeout,
        ureq::Error::HostNotFound => TransportKind::Resolve,
        ureq::Error::ConnectionFailed => TransportKind::Connect,
        ureq::Error::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => TransportKind::Connect,
            kind => TransportKind::Io(kind),
        },
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => TransportKind::Redirect,
        ureq::Error::Tls(_) => TransportKind::Tls,
        ureq::Error::Protocol(_) | ureq::Error::Http(_) | ureq::Error::BadUri(_) => TransportKind::Protocol,
        _ => TransportKind::Other,
    }
}

impl Transport for UreqTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(Error::PayloadTooLarge {
                what: "request body",
                max: MAX_REQUEST_BYTES,
                got: body.len(),
            });
        }
        let url = format!("{}{}", self.base, path);
        let mut response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(body)
            .map_err(|e| Error::Transport {
                op: "send",
                kind: classify(&e),
            })?;
        let status = response.status().as_u16();
        if status == 429 {
            // Read `Retry-After` as seconds; an HTTP-date or anything else
            // is reported as no stated wait.
            let retry_after_secs = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            return Err(Error::RateLimited { retry_after_secs });
        }
        if status != 200 {
            return Err(Error::HttpStatus { status });
        }
        // The cap is per endpoint, because history replies grow with what
        // they report. A body past it is reported as `PayloadTooLarge`.
        let cap = max_response_bytes(path);
        let limit = u64::try_from(cap).unwrap_or(u64::MAX);
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => Error::PayloadTooLarge {
                    what: "response body",
                    max: cap,
                    got: cap + 1,
                },
                other => Error::Transport {
                    op: "read body",
                    kind: classify(&other),
                },
            })
    }
}
