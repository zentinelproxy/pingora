// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{server::handshake, server::handshake_with_callback, TlsStream};
use log::{debug, warn};
use pingora_error::ErrorType::InternalError;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ClientCertVerifier;
use pingora_rustls::ServerConfig;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};

use crate::protocols::{ALPN, IO};

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: String,
    key_path: String,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
    server_config: Option<ServerConfig>,
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor {
        // rustls 0.23+ requires an explicit CryptoProvider.
        pingora_rustls::install_default_crypto_provider();

        let mut config = match self.server_config {
            // A caller-supplied config already carries its own certificate
            // resolver, client auth policy, protocol versions and cipher
            // suites. Nothing here may override those.
            Some(config) => {
                if self.client_cert_verifier.is_some() {
                    warn!(
                        "TlsSettings: ignoring the client certificate verifier set via \
                         set_client_cert_verifier(), because this endpoint was built from \
                         a caller-supplied ServerConfig. Client authentication is whatever \
                         that ServerConfig specifies."
                    );
                }
                config
            }
            None => {
                let Ok(Some((certs, key))) =
                    load_certs_and_key_files(&self.cert_path, &self.key_path)
                else {
                    panic!(
                        "Failed to load provided certificates \"{}\" or key \"{}\".",
                        self.cert_path, self.key_path
                    )
                };

                let builder = ServerConfig::builder_with_protocol_versions(&[
                    &version::TLS12,
                    &version::TLS13,
                ]);
                let builder = if let Some(verifier) = self.client_cert_verifier {
                    builder.with_client_cert_verifier(verifier)
                } else {
                    builder.with_no_client_auth()
                };
                builder
                    .with_single_cert(certs, key)
                    .explain_err(InternalError, |e| {
                        format!("Failed to create server listener config: {e}")
                    })
                    .unwrap()
            }
        };

        if let Some(alpn_protocols) = self.alpn_protocols {
            config.alpn_protocols = alpn_protocols;
        }

        Acceptor {
            acceptor: RusTlsAcceptor::from(Arc::new(config)),
            callbacks: None,
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    pub fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    /// Configure mTLS by providing a rustls client certificate verifier.
    pub fn set_client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) {
        self.client_cert_verifier = Some(verifier);
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            client_cert_verifier: None,
            server_config: None,
        })
    }

    /// Build the endpoint from a fully constructed rustls [`ServerConfig`].
    ///
    /// [`TlsSettings::intermediate`] loads a single certificate and applies a
    /// fixed profile: TLS 1.2 and 1.3, the provider's default cipher suites,
    /// and no client authentication. That is the right default, but it leaves
    /// no way to express anything rustls supports beyond it. This constructor
    /// takes the `ServerConfig` as given, so the caller can supply:
    ///
    /// * a [`ResolvesServerCert`] implementation, to pick a certificate per
    ///   SNI hostname rather than serving one certificate to every client
    /// * a narrower protocol version or cipher suite selection
    /// * a client certificate verifier, for mTLS
    /// * session storage and ticketing policy
    ///
    /// Only [`enable_h2`](Self::enable_h2) and [`set_alpn`](Self::set_alpn)
    /// still apply on top; they overwrite `alpn_protocols` on the supplied
    /// config. Every other setter is ignored on this path, since the config is
    /// already complete — [`build`](Self::build) logs a warning if a client
    /// certificate verifier was set that it has to discard.
    ///
    /// Unlike `intermediate`, this cannot panic on certificate loading: the
    /// caller has already loaded and validated the certificates, and so gets
    /// to report failures in its own terms rather than aborting the process.
    ///
    /// [`ResolvesServerCert`]: https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html
    pub fn with_server_config(config: ServerConfig) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_path: String::new(),
            key_path: String::new(),
            client_cert_verifier: None,
            server_config: Some(config),
        })
    }

    pub fn with_callbacks() -> Result<Self>
    where
        Self: Sized,
    {
        // TODO: verify if/how callback in handshake can be done using Rustls
        Error::e_explain(
            InternalError,
            "Certificate callbacks are not supported with feature \"rustls\".",
        )
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // TODO: be able to offload this handshake in a thread pool
        if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(self, stream, cb).await
        } else {
            handshake(self, stream).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_rustls::version;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    /// A resolver is the reason `with_server_config` exists: it is how a
    /// caller serves a different certificate per SNI hostname. Returning
    /// `None` is a valid response (no certificate for that name), which keeps
    /// this fixture free of key material.
    #[derive(Debug)]
    struct NoCerts;

    impl ResolvesServerCert for NoCerts {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    fn config_with_resolver() -> ServerConfig {
        pingora_rustls::install_default_crypto_provider();
        ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCerts))
    }

    /// The point of the prebuilt path: the caller has already loaded its own
    /// key material, so `build()` must not go looking for certificate files.
    /// `cert_path` and `key_path` are empty here, which the `intermediate`
    /// path would panic on (see below).
    #[test]
    fn prebuilt_config_does_not_read_certificate_files() {
        let settings = TlsSettings::with_server_config(config_with_resolver()).unwrap();
        assert!(settings.cert_path.is_empty());
        assert!(settings.key_path.is_empty());

        // Must not panic despite there being no certificate files to load.
        let _acceptor = settings.build();
    }

    /// The contrast that gives the test above its meaning.
    #[test]
    #[should_panic(expected = "Failed to load provided certificates")]
    fn certificate_loading_path_still_panics_on_missing_files() {
        TlsSettings::intermediate("/nonexistent/cert.pem", "/nonexistent/key.pem")
            .unwrap()
            .build();
    }

    /// ALPN is the one setting that still layers on top of a supplied config,
    /// because `enable_h2` is how callers opt into HTTP/2 on any endpoint.
    #[test]
    fn enable_h2_applies_on_top_of_a_prebuilt_config() {
        let mut settings = TlsSettings::with_server_config(config_with_resolver()).unwrap();
        assert!(settings
            .server_config
            .as_ref()
            .unwrap()
            .alpn_protocols
            .is_empty());

        settings.enable_h2();
        assert_eq!(
            settings.alpn_protocols,
            Some(ALPN::H2H1.to_wire_protocols())
        );

        let _acceptor = settings.build();
    }

    /// A supplied config decides its own client authentication policy, so a
    /// verifier set through the setter has nowhere to go. `build()` warns
    /// rather than silently implying mTLS is active.
    #[test]
    fn prebuilt_config_keeps_its_own_client_auth_policy() {
        let mut settings = TlsSettings::with_server_config(config_with_resolver()).unwrap();
        settings.set_client_cert_verifier(rustls::server::WebPkiClientVerifier::no_client_auth());

        let _acceptor = settings.build();
    }
}
