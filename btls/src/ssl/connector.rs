use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use crate::dh::Dh;
use crate::error::ErrorStack;
use crate::ssl::{
    HandshakeError, Ssl, SslContext, SslContextBuilder, SslContextRef, SslMethod, SslMode,
    SslOptions, SslRef, SslSignatureAlgorithm, SslStream, SslVerifyMode,
};
use crate::version;
use std::net::IpAddr;

use super::MidHandshakeSslStream;

const FFDHE_2048: &str = "
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
";

const DEFAULT_HTTP_ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];
const DEFAULT_VERIFY_ALGORITHM_PREFS: [SslSignatureAlgorithm; 9] = [
    SslSignatureAlgorithm::ED25519,
    SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
    SslSignatureAlgorithm::RSA_PKCS1_SHA256,
    SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
    SslSignatureAlgorithm::RSA_PKCS1_SHA384,
    SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
    SslSignatureAlgorithm::RSA_PKCS1_SHA512,
];

const CHROME_FINGERPRINT_PROFILE: ResolvedFingerprintProfile = ResolvedFingerprintProfile {
    name: "chrome",
    cipher_list: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:\
                  TLS_CHACHA20_POLY1305_SHA256:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    curves_list: "X25519:P-256:P-384",
    permute_extensions: true,
    preserve_tls13_cipher_list: true,
    verify_algorithm_prefs: &DEFAULT_VERIFY_ALGORITHM_PREFS,
    default_alpn_protocols: &DEFAULT_HTTP_ALPN_PROTOCOLS,
};

const SAFARI_FINGERPRINT_PROFILE: ResolvedFingerprintProfile = ResolvedFingerprintProfile {
    name: "safari",
    cipher_list: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:\
                  TLS_CHACHA20_POLY1305_SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    curves_list: "X25519:P-256:P-384:P-521",
    permute_extensions: false,
    preserve_tls13_cipher_list: true,
    verify_algorithm_prefs: &DEFAULT_VERIFY_ALGORITHM_PREFS,
    default_alpn_protocols: &DEFAULT_HTTP_ALPN_PROTOCOLS,
};

/// Browser-like TLS fingerprint presets for client handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintProfile {
    Chrome,
    Safari,
}

impl FingerprintProfile {
    /// Returns the stable profile name used for logging and config parsing.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Safari => "safari",
        }
    }

    /// Resolves the preset into the concrete BoringSSL builder settings.
    #[must_use]
    pub fn resolve(self) -> ResolvedFingerprintProfile {
        match self {
            Self::Chrome => CHROME_FINGERPRINT_PROFILE,
            Self::Safari => SAFARI_FINGERPRINT_PROFILE,
        }
    }
}

impl FromStr for FingerprintProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "chrome" => Ok(Self::Chrome),
            "ios" | "safari" => Ok(Self::Safari),
            _ => Err("unknown fingerprint profile"),
        }
    }
}

/// A fully resolved TLS fingerprint preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedFingerprintProfile {
    name: &'static str,
    cipher_list: &'static str,
    curves_list: &'static str,
    permute_extensions: bool,
    preserve_tls13_cipher_list: bool,
    verify_algorithm_prefs: &'static [SslSignatureAlgorithm],
    default_alpn_protocols: &'static [&'static [u8]],
}

impl ResolvedFingerprintProfile {
    #[must_use]
    pub fn name(self) -> &'static str {
        self.name
    }

    #[must_use]
    pub fn cipher_list(self) -> &'static str {
        self.cipher_list
    }

    #[must_use]
    pub fn curves_list(self) -> &'static str {
        self.curves_list
    }

    #[must_use]
    pub fn permute_extensions(self) -> bool {
        self.permute_extensions
    }

    #[must_use]
    pub fn preserve_tls13_cipher_list(self) -> bool {
        self.preserve_tls13_cipher_list
    }

    #[must_use]
    pub fn verify_algorithm_prefs(self) -> &'static [SslSignatureAlgorithm] {
        self.verify_algorithm_prefs
    }

    #[must_use]
    pub fn default_alpn_protocols(self) -> &'static [&'static [u8]] {
        self.default_alpn_protocols
    }
}

/// A caller-provided TLS fingerprint profile.
///
/// This is the raw override form of [`FingerprintProfile`]. It lets higher
/// layers keep their own browser/profile registry while still applying the
/// concrete TLS settings through this connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientProfileSpec {
    name: Option<String>,
    cipher_list: String,
    curves_list: String,
    permute_extensions: bool,
    preserve_tls13_cipher_list: bool,
    verify_algorithm_prefs: Vec<SslSignatureAlgorithm>,
    default_alpn_protocols: Vec<Vec<u8>>,
}

impl TlsClientProfileSpec {
    /// Creates a raw TLS fingerprint profile spec.
    pub fn new<I>(
        cipher_list: impl Into<String>,
        curves_list: impl Into<String>,
        verify_algorithm_prefs: I,
    ) -> Self
    where
        I: IntoIterator<Item = SslSignatureAlgorithm>,
    {
        Self {
            name: None,
            cipher_list: cipher_list.into(),
            curves_list: curves_list.into(),
            permute_extensions: false,
            preserve_tls13_cipher_list: false,
            verify_algorithm_prefs: verify_algorithm_prefs.into_iter().collect(),
            default_alpn_protocols: Vec::new(),
        }
    }

    /// Sets a stable profile name for diagnostics.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets whether ClientHello extensions should be permuted.
    pub fn permute_extensions(mut self, enabled: bool) -> Self {
        self.permute_extensions = enabled;
        self
    }

    /// Sets whether the configured TLS 1.3 cipher list order is preserved.
    pub fn preserve_tls13_cipher_list(mut self, enabled: bool) -> Self {
        self.preserve_tls13_cipher_list = enabled;
        self
    }

    /// Sets default ALPN protocols used when [`TlsClientOptions`] has no ALPN override.
    pub fn default_alpn_protocols<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.default_alpn_protocols = protocols
            .into_iter()
            .map(|protocol| protocol.as_ref().to_vec())
            .collect();
        self
    }

    /// Returns the optional profile name.
    #[must_use]
    pub fn name_ref(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the configured cipher list.
    #[must_use]
    pub fn cipher_list(&self) -> &str {
        &self.cipher_list
    }

    /// Returns the configured curves list.
    #[must_use]
    pub fn curves_list(&self) -> &str {
        &self.curves_list
    }

    /// Returns whether ClientHello extensions should be permuted.
    #[must_use]
    pub fn permute_extensions_enabled(&self) -> bool {
        self.permute_extensions
    }

    /// Returns whether the configured TLS 1.3 cipher list order is preserved.
    #[must_use]
    pub fn preserve_tls13_cipher_list_enabled(&self) -> bool {
        self.preserve_tls13_cipher_list
    }

    /// Returns the configured signature verification algorithms.
    #[must_use]
    pub fn verify_algorithm_prefs(&self) -> &[SslSignatureAlgorithm] {
        &self.verify_algorithm_prefs
    }

    /// Returns default ALPN protocols used when [`TlsClientOptions`] has no ALPN override.
    #[must_use]
    pub fn default_alpn_protocols_ref(&self) -> &[Vec<u8>] {
        &self.default_alpn_protocols
    }
}

/// High-level client TLS configuration for browser-like handshakes.
#[must_use]
#[derive(Debug, Clone)]
pub struct TlsClientOptions {
    fingerprint_profile: Option<FingerprintProfile>,
    fingerprint_spec: Option<TlsClientProfileSpec>,
    alpn_protocols: Option<Vec<Vec<u8>>>,
    session_tickets: bool,
}

impl Default for TlsClientOptions {
    fn default() -> Self {
        Self {
            fingerprint_profile: None,
            fingerprint_spec: None,
            alpn_protocols: None,
            session_tickets: true,
        }
    }
}

impl TlsClientOptions {
    /// Creates a new empty option set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Selects a browser fingerprint preset.
    pub fn fingerprint_profile(mut self, profile: FingerprintProfile) -> Self {
        self.fingerprint_profile = Some(profile);
        self.fingerprint_spec = None;
        self
    }

    /// Selects a caller-provided TLS fingerprint profile.
    pub fn fingerprint_spec(mut self, spec: TlsClientProfileSpec) -> Self {
        self.fingerprint_profile = None;
        self.fingerprint_spec = Some(spec);
        self
    }

    /// Overrides the ALPN protocol list.
    pub fn alpn_protocols<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn_protocols = Some(
            protocols
                .into_iter()
                .map(|protocol| protocol.as_ref().to_vec())
                .collect(),
        );
        self
    }

    /// Enables or disables session tickets.
    pub fn session_tickets(mut self, enabled: bool) -> Self {
        self.session_tickets = enabled;
        self
    }

    /// Returns the resolved fingerprint preset, if any.
    #[must_use]
    pub fn resolved_fingerprint_profile(&self) -> Option<ResolvedFingerprintProfile> {
        self.fingerprint_profile.map(FingerprintProfile::resolve)
    }

    /// Returns the caller-provided TLS fingerprint profile, if any.
    #[must_use]
    pub fn fingerprint_spec_ref(&self) -> Option<&TlsClientProfileSpec> {
        self.fingerprint_spec.as_ref()
    }

    /// Returns whether session tickets are enabled.
    #[must_use]
    pub fn session_tickets_enabled(&self) -> bool {
        self.session_tickets
    }

    fn encoded_alpn_protocols(&self) -> Result<Option<Vec<u8>>, ErrorStack> {
        if let Some(protocols) = self.alpn_protocols.as_ref() {
            return encode_alpn_protocols(protocols.iter().map(Vec::as_slice)).map(Some);
        }

        if let Some(spec) = self.fingerprint_spec.as_ref() {
            if spec.default_alpn_protocols_ref().is_empty() {
                return Ok(None);
            }
            return encode_alpn_protocols(
                spec.default_alpn_protocols_ref().iter().map(Vec::as_slice),
            )
            .map(Some);
        }

        self.resolved_fingerprint_profile()
            .map(|profile| encode_alpn_protocols(profile.default_alpn_protocols().iter().copied()))
            .transpose()
    }
}

fn encode_alpn_protocols<'a, I>(protocols: I) -> Result<Vec<u8>, ErrorStack>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut encoded = Vec::new();
    for protocol in protocols {
        let len = u8::try_from(protocol.len())
            .map_err(|_| ErrorStack::internal_error_str("ALPN protocol too long"))?;
        encoded.push(len);
        encoded.extend_from_slice(protocol);
    }
    Ok(encoded)
}

#[allow(clippy::inconsistent_digit_grouping)]
fn ctx(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
    let mut ctx = SslContextBuilder::new(method)?;

    let mut opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    opts &= !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS;

    ctx.set_options(opts);

    let mut mode =
        SslMode::AUTO_RETRY | SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE;

    // This is quite a useful optimization for saving memory, but historically
    // caused CVEs in OpenSSL pre-1.0.1h, according to
    // https://bugs.python.org/issue25672
    if version::number() >= 0x1000_1080 {
        mode |= SslMode::RELEASE_BUFFERS;
    }

    ctx.set_mode(mode);

    Ok(ctx)
}

/// A type which wraps client-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, hostname verification, and more.
///
/// OpenSSL's built in hostname verification is used when linking against OpenSSL 1.0.2 or 1.1.0,
/// and a custom implementation is used when linking against OpenSSL 1.0.1.
#[derive(Clone, Debug)]
pub struct SslConnector(SslContext);

impl SslConnector {
    /// Creates a new builder for TLS connections.
    ///
    /// The default configuration is subject to change, and is currently derived from Python.
    pub fn builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_default_verify_paths()?;
        ctx.set_cipher_list(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
        )?;
        ctx.set_verify(SslVerifyMode::PEER);

        Ok(SslConnectorBuilder(ctx))
    }

    /// Creates a bare builder for TLS connections without default CA certificates.
    ///
    /// The caller is responsible for providing a custom certificate store.
    pub fn bare_builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_cipher_list(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
        )?;

        Ok(SslConnectorBuilder(ctx))
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI and hostname verification.
    pub fn setup_connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        self.configure()?.setup_connect(domain, stream)
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Returns a structure allowing for configuration of a single TLS session before connection.
    pub fn configure(&self) -> Result<ConnectConfiguration, ErrorStack> {
        Ssl::new(&self.0).map(|ssl| ConnectConfiguration {
            ssl,
            sni: true,
            verify_hostname: true,
        })
    }

    /// Consumes the `SslConnector`, returning the inner raw `SslContext`.
    #[must_use]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslConnector`s.
pub struct SslConnectorBuilder(SslContextBuilder);

impl SslConnectorBuilder {
    /// Applies high-level client TLS options to the connector builder.
    pub fn apply_client_options(&mut self, options: &TlsClientOptions) -> Result<(), ErrorStack> {
        if let Some(spec) = options.fingerprint_spec_ref() {
            self.apply_fingerprint_settings(
                spec.cipher_list(),
                spec.curves_list(),
                spec.permute_extensions_enabled(),
                spec.preserve_tls13_cipher_list_enabled(),
                spec.verify_algorithm_prefs(),
            )?;
        } else if let Some(profile) = options.resolved_fingerprint_profile() {
            self.apply_fingerprint_settings(
                profile.cipher_list(),
                profile.curves_list(),
                profile.permute_extensions(),
                profile.preserve_tls13_cipher_list(),
                profile.verify_algorithm_prefs(),
            )?;
        }

        if options.session_tickets_enabled() {
            self.clear_options(SslOptions::NO_TICKET);
        } else {
            self.set_options(SslOptions::NO_TICKET);
        }

        if let Some(alpn) = options.encoded_alpn_protocols()? {
            self.set_alpn_protos(&alpn)?;
        }

        Ok(())
    }

    fn apply_fingerprint_settings(
        &mut self,
        cipher_list: &str,
        curves_list: &str,
        permute_extensions: bool,
        preserve_tls13_cipher_list: bool,
        verify_algorithm_prefs: &[SslSignatureAlgorithm],
    ) -> Result<(), ErrorStack> {
        #[cfg(not(feature = "fips"))]
        self.set_preserve_tls13_cipher_list(preserve_tls13_cipher_list);
        self.set_cipher_list(cipher_list)?;
        self.set_curves_list(curves_list)?;
        self.set_permute_extensions(permute_extensions);
        self.set_verify_algorithm_prefs(verify_algorithm_prefs)?;
        Ok(())
    }

    /// Consumes the builder, returning an `SslConnector`.
    #[must_use]
    pub fn build(self) -> SslConnector {
        SslConnector(self.0.build())
    }
}

impl Deref for SslConnectorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslConnectorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

/// A type which allows for configuration of a client-side TLS session before connection.
pub struct ConnectConfiguration {
    ssl: Ssl,
    sni: bool,
    verify_hostname: bool,
}

impl ConnectConfiguration {
    /// A builder-style version of `set_use_server_name_indication`.
    #[must_use]
    pub fn use_server_name_indication(mut self, use_sni: bool) -> ConnectConfiguration {
        self.set_use_server_name_indication(use_sni);
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Defaults to `true`.
    pub fn set_use_server_name_indication(&mut self, use_sni: bool) {
        self.sni = use_sni;
    }

    /// A builder-style version of `set_verify_hostname`.
    #[must_use]
    pub fn verify_hostname(mut self, verify_hostname: bool) -> ConnectConfiguration {
        self.set_verify_hostname(verify_hostname);
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname verification is not
    /// used, *any* valid certificate for *any* site will be trusted for use from any other. This
    /// introduces a significant vulnerability to man-in-the-middle attacks.
    pub fn set_verify_hostname(&mut self, verify_hostname: bool) {
        self.verify_hostname = verify_hostname;
    }

    /// Returns an [`Ssl`] configured to connect to the provided domain.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    pub fn into_ssl(mut self, domain: &str) -> Result<Ssl, ErrorStack> {
        if self.sni && domain.parse::<IpAddr>().is_err() {
            self.ssl.set_hostname(domain)?;
        }

        if self.verify_hostname {
            setup_verify_hostname(&mut self.ssl, domain)?;
        }

        Ok(self.ssl)
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::into_ssl`] and
    /// [`Ssl::setup_connect`].
    pub fn setup_connect<S>(
        self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        Ok(self.into_ssl(domain)?.setup_connect(stream))
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn connect<S>(self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }
}

impl Deref for ConnectConfiguration {
    type Target = SslRef;

    fn deref(&self) -> &SslRef {
        &self.ssl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_profile_parses_aliases() {
        assert_eq!("chrome".parse(), Ok(FingerprintProfile::Chrome));
        assert_eq!("ios".parse(), Ok(FingerprintProfile::Safari));
        assert_eq!("safari".parse(), Ok(FingerprintProfile::Safari));
    }

    #[test]
    fn tls_client_options_encode_profile_default_alpn() {
        let options = TlsClientOptions::new().fingerprint_profile(FingerprintProfile::Chrome);

        assert_eq!(
            options.encoded_alpn_protocols().unwrap(),
            Some(b"\x02h2\x08http/1.1".to_vec())
        );
    }

    #[test]
    fn tls_client_options_custom_alpn_overrides_profile_default() {
        let options = TlsClientOptions::new()
            .fingerprint_profile(FingerprintProfile::Chrome)
            .alpn_protocols([b"foo".as_slice(), b"bar".as_slice()]);

        assert_eq!(
            options.encoded_alpn_protocols().unwrap(),
            Some(b"\x03foo\x03bar".to_vec())
        );
    }

    #[test]
    fn tls_client_options_encode_raw_profile_default_alpn() {
        let options = TlsClientOptions::new().fingerprint_spec(
            TlsClientProfileSpec::new(
                CHROME_FINGERPRINT_PROFILE.cipher_list(),
                CHROME_FINGERPRINT_PROFILE.curves_list(),
                DEFAULT_VERIFY_ALGORITHM_PREFS,
            )
            .default_alpn_protocols([b"h3".as_slice(), b"h2".as_slice()])
            .permute_extensions(true)
            .preserve_tls13_cipher_list(true),
        );

        assert_eq!(
            options.encoded_alpn_protocols().unwrap(),
            Some(b"\x02h3\x02h2".to_vec())
        );
        assert_eq!(
            options.fingerprint_spec_ref().unwrap().cipher_list(),
            CHROME_FINGERPRINT_PROFILE.cipher_list()
        );
    }

    #[test]
    fn tls_client_options_custom_alpn_overrides_raw_profile_default() {
        let options = TlsClientOptions::new()
            .fingerprint_spec(
                TlsClientProfileSpec::new(
                    SAFARI_FINGERPRINT_PROFILE.cipher_list(),
                    SAFARI_FINGERPRINT_PROFILE.curves_list(),
                    DEFAULT_VERIFY_ALGORITHM_PREFS,
                )
                .default_alpn_protocols([b"h2".as_slice()]),
            )
            .alpn_protocols([b"custom".as_slice()]);

        assert_eq!(
            options.encoded_alpn_protocols().unwrap(),
            Some(b"\x06custom".to_vec())
        );
    }

    #[test]
    fn apply_client_options_toggles_session_tickets() {
        let mut builder = SslConnector::bare_builder(SslMethod::tls()).unwrap();
        builder.set_options(SslOptions::NO_TICKET);

        builder
            .apply_client_options(&TlsClientOptions::new().session_tickets(true))
            .unwrap();
        assert!(!builder.options().contains(SslOptions::NO_TICKET));

        builder
            .apply_client_options(&TlsClientOptions::new().session_tickets(false))
            .unwrap();
        assert!(builder.options().contains(SslOptions::NO_TICKET));
    }

    #[test]
    fn apply_client_options_accepts_fingerprint_profile() {
        let mut builder = SslConnector::bare_builder(SslMethod::tls()).unwrap();

        builder
            .apply_client_options(
                &TlsClientOptions::new()
                    .fingerprint_profile(FingerprintProfile::Safari)
                    .session_tickets(false),
            )
            .unwrap();

        assert!(builder.options().contains(SslOptions::NO_TICKET));
        assert_eq!(
            TlsClientOptions::new()
                .fingerprint_profile(FingerprintProfile::Safari)
                .resolved_fingerprint_profile()
                .unwrap()
                .name(),
            "safari"
        );
    }

    #[test]
    fn apply_client_options_accepts_raw_fingerprint_spec() {
        let mut builder = SslConnector::bare_builder(SslMethod::tls()).unwrap();

        builder
            .apply_client_options(
                &TlsClientOptions::new()
                    .fingerprint_spec(
                        TlsClientProfileSpec::new(
                            CHROME_FINGERPRINT_PROFILE.cipher_list(),
                            CHROME_FINGERPRINT_PROFILE.curves_list(),
                            DEFAULT_VERIFY_ALGORITHM_PREFS,
                        )
                        .name("chrome_131")
                        .permute_extensions(true)
                        .preserve_tls13_cipher_list(true),
                    )
                    .session_tickets(false),
            )
            .unwrap();

        assert!(builder.options().contains(SslOptions::NO_TICKET));
        assert_eq!(
            TlsClientOptions::new()
                .fingerprint_spec(
                    TlsClientProfileSpec::new(
                        CHROME_FINGERPRINT_PROFILE.cipher_list(),
                        CHROME_FINGERPRINT_PROFILE.curves_list(),
                        DEFAULT_VERIFY_ALGORITHM_PREFS,
                    )
                    .name("chrome_131"),
                )
                .fingerprint_spec_ref()
                .unwrap()
                .name_ref(),
            Some("chrome_131")
        );
    }
}

impl DerefMut for ConnectConfiguration {
    fn deref_mut(&mut self) -> &mut SslRef {
        &mut self.ssl
    }
}

/// A type which wraps server-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, and more.
#[derive(Clone)]
pub struct SslAcceptor(SslContext);

impl SslAcceptor {
    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of version 5 of Mozilla's server side TLS
    /// recommendations. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn mozilla_intermediate_v5(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
        let dh = Dh::params_from_pem(FFDHE_2048.as_bytes())?;
        ctx.set_tmp_dh(&dh)?;
        ctx.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
             ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
             DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of version 4 of Mozilla's server side TLS
    /// recommendations. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    // FIXME remove in next major version
    pub fn mozilla_intermediate(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        ctx.set_options(SslOptions::NO_TLSV1_3);
        let dh = Dh::params_from_pem(FFDHE_2048.as_bytes())?;
        ctx.set_tmp_dh(&dh)?;
        ctx.set_cipher_list(
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
             ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
             DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
             ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
             ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
             DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
             EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:\
             AES256-SHA:DES-CBC3-SHA:!DSS",
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Creates a new builder configured to connect to modern clients.
    ///
    /// This corresponds to the modern configuration of version 4 of Mozilla's server side TLS recommendations.
    /// See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    // FIXME remove in next major version
    pub fn mozilla_modern(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(
            SslOptions::CIPHER_SERVER_PREFERENCE | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1,
        );
        ctx.set_options(SslOptions::NO_TLSV1_3);
        ctx.set_cipher_list(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
             ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Initiates a server-side TLS handshake on a stream.
    ///
    /// See [`Ssl::setup_accept`] for more details.
    pub fn setup_accept<S>(&self, stream: S) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        let ssl = Ssl::new(&self.0)?;

        Ok(ssl.setup_accept(stream))
    }

    /// Attempts a server-side TLS handshake on a stream.
    ///
    /// This is a convenience method which combines [`Self::setup_accept`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn accept<S>(&self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_accept(stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Consumes the `SslAcceptor`, returning the inner raw `SslContext`.
    #[must_use]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslAcceptor`s.
pub struct SslAcceptorBuilder(SslContextBuilder);

impl SslAcceptorBuilder {
    /// Consumes the builder, returning a `SslAcceptor`.
    #[must_use]
    pub fn build(self) -> SslAcceptor {
        SslAcceptor(self.0.build())
    }
}

impl Deref for SslAcceptorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslAcceptorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

fn setup_verify_hostname(ssl: &mut SslRef, domain: &str) -> Result<(), ErrorStack> {
    use crate::x509::verify::X509CheckFlags;

    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match domain.parse() {
        Ok(ip) => param.set_ip(ip),
        Err(_) => param.set_host(domain),
    }
}
