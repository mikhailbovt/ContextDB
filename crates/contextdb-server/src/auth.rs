use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextdb_service::{ErrorCode, ServiceError, ServiceResult};
use zeroize::Zeroizing;

/// Header/metadata carrying the trusted gateway identity.
pub const GATEWAY_ID_HEADER: &str = "x-contextdb-gateway-id";
/// Header/metadata carrying the compact exact-request gateway assertion.
pub const GATEWAY_ATTESTATION_HEADER: &str = "x-contextdb-gateway-attestation";
/// Exact-request gateway attestation protocol version.
pub const GATEWAY_ATTESTATION_VERSION: &str = "v2";
/// Largest accepted UTF-8 gateway identity header/metadata value.
pub const MAX_GATEWAY_ID_BYTES: usize = 1_024;
/// Largest accepted compact attestation header/metadata value.
pub const MAX_GATEWAY_ATTESTATION_BYTES: usize = 224;
/// Number of bytes in the gateway-supplied unique nonce.
pub const GATEWAY_NONCE_BYTES: usize = 16;
/// Largest accepted lifetime of one exact-request assertion.
pub const MAX_GATEWAY_ATTESTATION_LIFETIME: Duration = Duration::from_secs(60);
/// Clock skew tolerated at either freshness boundary.
pub const MAX_GATEWAY_ATTESTATION_CLOCK_SKEW: Duration = Duration::from_secs(5);

const DEFAULT_ATTESTATION_LIFETIME: Duration = Duration::from_secs(30);
const MAX_REPLAY_ENTRIES: usize = 65_536;

/// Transport namespace included in an exact-request gateway transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayTransport {
    /// HTTP/JSON bytes exactly as sent after deterministic SDK serialization.
    Http,
    /// Deterministic canonical Prost semantic bytes after bounded wire admission.
    Grpc,
}

impl GatewayTransport {
    const fn canonical_id(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Grpc => "grpc",
        }
    }
}

/// Exact compatibility-network method used as an operation identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyNetworkOperation {
    /// `POST /v1/observations`.
    HttpObserve,
    /// `POST /v1/recall`.
    HttpRecall,
    /// `POST /v1/recall/explain`.
    HttpExplainRecall,
    /// `POST /v1/archive/export`.
    HttpExport,
    /// `POST /v1/archive/import`.
    HttpImport,
    /// `POST /v1/verify`.
    HttpVerify,
    /// `contextdb.v1.ObservationService/Observe`.
    GrpcObserve,
    /// `contextdb.v1.ObservationService/ObserveStream`.
    GrpcObserveStream,
    /// `contextdb.v1.RecallService/Recall`.
    GrpcRecall,
    /// `contextdb.v1.RecallService/RecallStream`.
    GrpcRecallStream,
    /// `contextdb.v1.RecallService/ContinueRecall`.
    GrpcContinueRecall,
    /// `contextdb.v1.RecallService/ExplainRecall`.
    GrpcExplainRecall,
    /// `contextdb.v1.ArchiveService/Export`.
    GrpcArchiveExport,
    /// `contextdb.v1.ArchiveService/Import`.
    GrpcArchiveImport,
    /// `contextdb.v1.MaintenanceService/Verify`.
    GrpcMaintenanceVerify,
}

impl LegacyNetworkOperation {
    #[cfg(any(feature = "http", feature = "server"))]
    pub(crate) const fn canonical_id(self) -> &'static str {
        match self {
            Self::HttpObserve => "POST:/v1/observations",
            Self::HttpRecall => "POST:/v1/recall",
            Self::HttpExplainRecall => "POST:/v1/recall/explain",
            Self::HttpExport => "POST:/v1/archive/export",
            Self::HttpImport => "POST:/v1/archive/import",
            Self::HttpVerify => "POST:/v1/verify",
            Self::GrpcObserve => "contextdb.v1.ObservationService/Observe",
            Self::GrpcObserveStream => "contextdb.v1.ObservationService/ObserveStream",
            Self::GrpcRecall => "contextdb.v1.RecallService/Recall",
            Self::GrpcRecallStream => "contextdb.v1.RecallService/RecallStream",
            Self::GrpcContinueRecall => "contextdb.v1.RecallService/ContinueRecall",
            Self::GrpcExplainRecall => "contextdb.v1.RecallService/ExplainRecall",
            Self::GrpcArchiveExport => "contextdb.v1.ArchiveService/Export",
            Self::GrpcArchiveImport => "contextdb.v1.ArchiveService/Import",
            Self::GrpcMaintenanceVerify => "contextdb.v1.MaintenanceService/Verify",
        }
    }
}

/// Trust-boundary contract used by HTTP and gRPC before an authenticated
/// request payload enters the canonical service.
///
/// A deployment gateway authenticates the original peer, then signs one v2
/// transcript containing the transport, exact operation, canonical request
/// bytes, freshness window, and unique nonce. Implementations must atomically
/// reject nonce replay.
pub trait GatewayAuthenticator: Send + Sync + 'static {
    /// Verifies and atomically consumes one exact-request assertion.
    fn verify_exact_request(
        &self,
        gateway_id: Option<&str>,
        attestation: Option<&str>,
        transport: GatewayTransport,
        operation: &str,
        canonical_body: &[u8],
    ) -> ServiceResult<()>;
}

/// Shared gateway verifier handle used by both network adapters.
pub type SharedGatewayAuthenticator = Arc<dyn GatewayAuthenticator>;

/// Keyed-BLAKE3 verifier for assertions emitted by one trusted gateway.
///
/// Clones share one bounded atomic replay cache. A verifier restart rejects
/// assertions issued before its new acceptance epoch. Multiple processes need
/// a deployment-level shared replay authority or single-verifier routing.
pub struct Blake3GatewayAuthenticator {
    gateway_id: String,
    key: Arc<Zeroizing<[u8; 32]>>,
    replay: Arc<Mutex<ReplayCache>>,
    clock: Arc<dyn Fn() -> ServiceResult<u64> + Send + Sync>,
    acceptance_epoch_ms: u64,
}

#[derive(Debug, Default)]
struct ReplayCache {
    expires_by_nonce: BTreeMap<[u8; GATEWAY_NONCE_BYTES], u64>,
    nonces_by_expiry: BTreeSet<(u64, [u8; GATEWAY_NONCE_BYTES])>,
}

impl Blake3GatewayAuthenticator {
    /// Creates a verifier for one configured gateway and non-zero shared key.
    pub fn new(gateway_id: impl Into<String>, key: [u8; 32]) -> ServiceResult<Self> {
        Self::new_with_clock(gateway_id, key, Arc::new(system_unix_millis))
    }

    fn new_with_clock(
        gateway_id: impl Into<String>,
        key: [u8; 32],
        clock: Arc<dyn Fn() -> ServiceResult<u64> + Send + Sync>,
    ) -> ServiceResult<Self> {
        let gateway_id = gateway_id.into();
        if gateway_id.trim().is_empty()
            || gateway_id.len() > MAX_GATEWAY_ID_BYTES
            || gateway_id.contains('\0')
        {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "gateway identity is invalid",
                false,
            ));
        }
        if key.iter().all(|byte| *byte == 0) {
            return Err(ServiceError::new(
                ErrorCode::InvalidArgument,
                "gateway attestation key must not be all zero",
                false,
            ));
        }
        let acceptance_epoch_ms = clock()?;
        Ok(Self {
            gateway_id,
            key: Arc::new(Zeroizing::new(key)),
            replay: Arc::new(Mutex::new(ReplayCache::default())),
            clock,
            acceptance_epoch_ms,
        })
    }

    /// Returns the configured public gateway identifier.
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    /// Creates a short-lived exact-request assertion using the current clock.
    ///
    /// The trusted gateway supplies a cryptographically unique 128-bit nonce.
    pub fn attest_exact_request(
        &self,
        transport: GatewayTransport,
        operation: &str,
        canonical_body: &[u8],
        nonce: [u8; GATEWAY_NONCE_BYTES],
    ) -> ServiceResult<String> {
        let issued_at_ms = (self.clock)()?;
        let expires_at_ms = issued_at_ms
            .checked_add(duration_millis(DEFAULT_ATTESTATION_LIFETIME))
            .ok_or_else(|| integrity_failure("gateway attestation expiry overflowed"))?;
        self.attest_exact_request_at(
            transport,
            operation,
            canonical_body,
            issued_at_ms,
            expires_at_ms,
            nonce,
        )
    }

    /// Creates a deterministic exact-request assertion for a caller-supplied
    /// issuance window. Intended for trusted gateways and conformance tests.
    pub fn attest_exact_request_at(
        &self,
        transport: GatewayTransport,
        operation: &str,
        canonical_body: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
        nonce: [u8; GATEWAY_NONCE_BYTES],
    ) -> ServiceResult<String> {
        validate_operation(operation)?;
        validate_window_shape(issued_at_ms, expires_at_ms)?;
        let body_digest = blake3::hash(canonical_body);
        let mac = exact_request_mac(
            &self.key,
            &self.gateway_id,
            transport,
            operation,
            body_digest.as_bytes(),
            issued_at_ms,
            expires_at_ms,
            &nonce,
        );
        Ok(format!(
            "{GATEWAY_ATTESTATION_VERSION}.{issued_at_ms}.{expires_at_ms}.{}.{}.{}",
            encode_lower_hex(&nonce),
            body_digest.to_hex(),
            mac.to_hex()
        ))
    }
}

impl Clone for Blake3GatewayAuthenticator {
    fn clone(&self) -> Self {
        Self {
            gateway_id: self.gateway_id.clone(),
            key: Arc::clone(&self.key),
            replay: Arc::clone(&self.replay),
            clock: Arc::clone(&self.clock),
            acceptance_epoch_ms: self.acceptance_epoch_ms,
        }
    }
}

impl std::fmt::Debug for Blake3GatewayAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Blake3GatewayAuthenticator")
            .field("gateway_id", &self.gateway_id)
            .field("acceptance_epoch_ms", &self.acceptance_epoch_ms)
            .finish_non_exhaustive()
    }
}

impl GatewayAuthenticator for Blake3GatewayAuthenticator {
    fn verify_exact_request(
        &self,
        gateway_id: Option<&str>,
        attestation: Option<&str>,
        transport: GatewayTransport,
        operation: &str,
        canonical_body: &[u8],
    ) -> ServiceResult<()> {
        validate_operation(operation)?;
        if gateway_id != Some(self.gateway_id.as_str()) {
            return Err(unauthorized_gateway());
        }
        let token = parse_token(attestation.ok_or_else(unauthorized_gateway)?)
            .ok_or_else(unauthorized_gateway)?;
        let now_ms = (self.clock)()?;
        validate_window_freshness(
            token.issued_at_ms,
            token.expires_at_ms,
            now_ms,
            self.acceptance_epoch_ms,
        )?;
        let actual_body_digest = blake3::hash(canonical_body);
        let expected_mac = exact_request_mac(
            &self.key,
            &self.gateway_id,
            transport,
            operation,
            token.body_digest.as_bytes(),
            token.issued_at_ms,
            token.expires_at_ms,
            &token.nonce,
        );
        let digest_matches =
            constant_time_eq(actual_body_digest.as_bytes(), token.body_digest.as_bytes());
        let mac_matches = constant_time_eq(token.mac.as_bytes(), expected_mac.as_bytes());
        if !(digest_matches & mac_matches) {
            return Err(unauthorized_gateway());
        }
        consume_nonce(&self.replay, token.nonce, token.expires_at_ms, now_ms)
    }
}

/// Fail-closed verifier used when a server has not configured a trusted
/// gateway. Every network method rejects before operation payload use.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectingGatewayAuthenticator;

impl GatewayAuthenticator for RejectingGatewayAuthenticator {
    fn verify_exact_request(
        &self,
        _gateway_id: Option<&str>,
        _attestation: Option<&str>,
        _transport: GatewayTransport,
        _operation: &str,
        _canonical_body: &[u8],
    ) -> ServiceResult<()> {
        Err(ServiceError::new(
            ErrorCode::Unauthorized,
            "no trusted authentication gateway is configured",
            false,
        )
        .with_context(
            Vec::new(),
            Some("gateway_attestation_required".to_owned()),
            Some("configure a trusted gateway authenticator".to_owned()),
            None,
        ))
    }
}

struct ParsedToken {
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; GATEWAY_NONCE_BYTES],
    body_digest: blake3::Hash,
    mac: blake3::Hash,
}

#[allow(
    clippy::too_many_arguments,
    reason = "every transcript field is explicit"
)]
fn exact_request_mac(
    key: &[u8; 32],
    gateway_id: &str,
    transport: GatewayTransport,
    operation: &str,
    body_digest: &[u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8; GATEWAY_NONCE_BYTES],
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(key);
    framed_update(&mut hasher, b"contextdb/gateway-exact-request/v2");
    framed_update(
        &mut hasher,
        &contextdb_service::SERVICE_SCHEMA_VERSION.to_le_bytes(),
    );
    framed_update(&mut hasher, gateway_id.as_bytes());
    framed_update(&mut hasher, transport.canonical_id().as_bytes());
    framed_update(&mut hasher, operation.as_bytes());
    framed_update(&mut hasher, body_digest);
    framed_update(&mut hasher, &issued_at_ms.to_le_bytes());
    framed_update(&mut hasher, &expires_at_ms.to_le_bytes());
    framed_update(&mut hasher, nonce);
    hasher.finalize()
}

fn framed_update(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn unauthorized_gateway() -> ServiceError {
    ServiceError::new(
        ErrorCode::Unauthorized,
        "trusted gateway exact-request attestation is missing, invalid, stale, or replayed",
        false,
    )
    .with_context(
        Vec::new(),
        Some("gateway_exact_request_attestation_invalid".to_owned()),
        Some("authenticate this exact request through a configured ContextDB gateway".to_owned()),
        None,
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn parse_token(value: &str) -> Option<ParsedToken> {
    if value.len() > MAX_GATEWAY_ATTESTATION_BYTES || !value.is_ascii() {
        return None;
    }
    let mut parts = value.split('.');
    if parts.next()? != GATEWAY_ATTESTATION_VERSION {
        return None;
    }
    let issued_at_ms = parse_canonical_u64(parts.next()?)?;
    let expires_at_ms = parse_canonical_u64(parts.next()?)?;
    let nonce = decode_lower_hex_16(parts.next()?)?;
    let body_digest_text = parts.next()?;
    let mac_text = parts.next()?;
    if parts.next().is_some() || !is_lower_hex(body_digest_text, 64) || !is_lower_hex(mac_text, 64)
    {
        return None;
    }
    Some(ParsedToken {
        issued_at_ms,
        expires_at_ms,
        nonce,
        body_digest: blake3::Hash::from_hex(body_digest_text).ok()?,
        mac: blake3::Hash::from_hex(mac_text).ok()?,
    })
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn decode_lower_hex_16(value: &str) -> Option<[u8; GATEWAY_NONCE_BYTES]> {
    if !is_lower_hex(value, GATEWAY_NONCE_BYTES * 2) {
        return None;
    }
    let mut output = [0_u8; GATEWAY_NONCE_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_lower_hex_digit(pair[0])? << 4) | decode_lower_hex_digit(pair[1])?;
    }
    Some(output)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn decode_lower_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_lower_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_operation(operation: &str) -> ServiceResult<()> {
    if operation.is_empty() || operation.len() > 1_024 || operation.contains('\0') {
        return Err(ServiceError::new(
            ErrorCode::InvalidArgument,
            "gateway request operation is invalid",
            false,
        ));
    }
    Ok(())
}

fn validate_window_shape(issued_at_ms: u64, expires_at_ms: u64) -> ServiceResult<()> {
    let lifetime = expires_at_ms
        .checked_sub(issued_at_ms)
        .ok_or_else(unauthorized_gateway)?;
    if lifetime == 0 || lifetime > duration_millis(MAX_GATEWAY_ATTESTATION_LIFETIME) {
        return Err(unauthorized_gateway());
    }
    Ok(())
}

fn validate_window_freshness(
    issued_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
    acceptance_epoch_ms: u64,
) -> ServiceResult<()> {
    validate_window_shape(issued_at_ms, expires_at_ms)?;
    let skew = duration_millis(MAX_GATEWAY_ATTESTATION_CLOCK_SKEW);
    if issued_at_ms < acceptance_epoch_ms
        || issued_at_ms > now_ms.saturating_add(skew)
        || expires_at_ms.saturating_add(skew) < now_ms
    {
        return Err(unauthorized_gateway());
    }
    Ok(())
}

fn consume_nonce(
    cache: &Mutex<ReplayCache>,
    nonce: [u8; GATEWAY_NONCE_BYTES],
    expires_at_ms: u64,
    now_ms: u64,
) -> ServiceResult<()> {
    let skew = duration_millis(MAX_GATEWAY_ATTESTATION_CLOCK_SKEW);
    let mut cache = cache
        .lock()
        .map_err(|_| integrity_failure("gateway replay cache lock is poisoned"))?;
    while let Some((expiry, nonce)) = cache.nonces_by_expiry.first().copied() {
        if expiry.saturating_add(skew) >= now_ms {
            break;
        }
        cache.nonces_by_expiry.pop_first();
        if cache.expires_by_nonce.get(&nonce) == Some(&expiry) {
            cache.expires_by_nonce.remove(&nonce);
        }
    }
    if cache.expires_by_nonce.contains_key(&nonce) {
        return Err(unauthorized_gateway());
    }
    if cache.expires_by_nonce.len() >= MAX_REPLAY_ENTRIES {
        return Err(ServiceError::new(
            ErrorCode::ResourceExhausted,
            "gateway replay cache is saturated with unexpired assertions",
            true,
        )
        .with_context(
            Vec::new(),
            Some("gateway_replay_cache_saturated".to_owned()),
            Some("retry after the shortest attestation window expires".to_owned()),
            None,
        ));
    }
    cache.expires_by_nonce.insert(nonce, expires_at_ms);
    cache.nonces_by_expiry.insert((expires_at_ms, nonce));
    Ok(())
}

fn system_unix_millis() -> ServiceResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| integrity_failure("system clock precedes the Unix epoch"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| integrity_failure("system clock does not fit the attestation timestamp"))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn integrity_failure(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::IntegrityFailure, message, false)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Barrier, Mutex as TestMutex};

    use super::*;

    fn verifier_at(now: Arc<AtomicU64>) -> Blake3GatewayAuthenticator {
        Blake3GatewayAuthenticator::new_with_clock(
            "gateway:test",
            [9; 32],
            Arc::new(move || Ok(now.load(Ordering::SeqCst))),
        )
        .expect("gateway verifier")
    }

    #[test]
    fn exact_attestation_is_request_bound_and_one_shot() {
        let verifier = verifier_at(Arc::new(AtomicU64::new(1_000_000)));
        let body = b"body";
        let token = verifier
            .attest_exact_request(GatewayTransport::Http, "POST:/v1/recall", body, [1; 16])
            .expect("token");
        verifier
            .verify_exact_request(
                Some("gateway:test"),
                Some(&token),
                GatewayTransport::Http,
                "POST:/v1/recall",
                body,
            )
            .expect("first use");
        assert_eq!(
            verifier
                .verify_exact_request(
                    Some("gateway:test"),
                    Some(&token),
                    GatewayTransport::Http,
                    "POST:/v1/recall",
                    body,
                )
                .expect_err("replay")
                .code,
            ErrorCode::Unauthorized
        );

        for (nonce, transport, operation, changed) in [
            (
                2,
                GatewayTransport::Grpc,
                "POST:/v1/recall",
                body.as_slice(),
            ),
            (
                3,
                GatewayTransport::Http,
                "POST:/v1/verify",
                body.as_slice(),
            ),
            (
                4,
                GatewayTransport::Http,
                "POST:/v1/recall",
                b"changed".as_slice(),
            ),
        ] {
            let token = verifier
                .attest_exact_request(GatewayTransport::Http, "POST:/v1/recall", body, [nonce; 16])
                .expect("variant token");
            assert_eq!(
                verifier
                    .verify_exact_request(
                        Some("gateway:test"),
                        Some(&token),
                        transport,
                        operation,
                        changed,
                    )
                    .expect_err("binding mismatch")
                    .code,
                ErrorCode::Unauthorized
            );
        }
    }

    #[test]
    fn concurrent_replay_consumption_has_exactly_one_winner() {
        const CONTENDERS: usize = 16;
        let verifier = Arc::new(verifier_at(Arc::new(AtomicU64::new(1_500_000))));
        let token = verifier
            .attest_exact_request(
                GatewayTransport::Http,
                "POST:/v1/recall",
                b"body",
                [0x44; 16],
            )
            .expect("token");
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let outcomes = Arc::new(TestMutex::new(Vec::with_capacity(CONTENDERS)));
        std::thread::scope(|scope| {
            for _ in 0..CONTENDERS {
                let verifier = Arc::clone(&verifier);
                let barrier = Arc::clone(&barrier);
                let outcomes = Arc::clone(&outcomes);
                let token = token.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let outcome = verifier.verify_exact_request(
                        Some("gateway:test"),
                        Some(&token),
                        GatewayTransport::Http,
                        "POST:/v1/recall",
                        b"body",
                    );
                    outcomes.lock().expect("outcomes").push(outcome);
                });
            }
        });
        let outcomes = outcomes.lock().expect("outcomes");
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(
            outcomes
                .iter()
                .filter_map(|outcome| outcome.as_ref().err())
                .all(|error| error.code == ErrorCode::Unauthorized)
        );
    }

    #[test]
    fn expiry_cleanup_clock_rollback_and_restart_fail_closed() {
        let now = Arc::new(AtomicU64::new(2_000_000));
        let verifier = verifier_at(Arc::clone(&now));
        let body = b"body";
        let first = verifier
            .attest_exact_request_at(
                GatewayTransport::Grpc,
                "service/Method",
                body,
                2_000_000,
                2_001_000,
                [5; 16],
            )
            .expect("short token");
        verifier
            .verify_exact_request(
                Some("gateway:test"),
                Some(&first),
                GatewayTransport::Grpc,
                "service/Method",
                body,
            )
            .expect("first use");
        now.store(2_010_000, Ordering::SeqCst);
        let reused = verifier
            .attest_exact_request_at(
                GatewayTransport::Grpc,
                "service/Method",
                body,
                2_010_000,
                2_020_000,
                [5; 16],
            )
            .expect("reused nonce after expiry");
        verifier
            .verify_exact_request(
                Some("gateway:test"),
                Some(&reused),
                GatewayTransport::Grpc,
                "service/Method",
                body,
            )
            .expect("expired entry pruned");

        now.store(1_900_000, Ordering::SeqCst);
        assert_eq!(
            verifier
                .verify_exact_request(
                    Some("gateway:test"),
                    Some(&reused),
                    GatewayTransport::Grpc,
                    "service/Method",
                    body,
                )
                .expect_err("clock rollback")
                .code,
            ErrorCode::Unauthorized
        );

        now.store(2_100_000, Ordering::SeqCst);
        let restarted = verifier_at(now);
        let old = restarted
            .attest_exact_request_at(
                GatewayTransport::Grpc,
                "service/Method",
                body,
                2_099_999,
                2_120_000,
                [6; 16],
            )
            .expect("old token shape");
        assert_eq!(
            restarted
                .verify_exact_request(
                    Some("gateway:test"),
                    Some(&old),
                    GatewayTransport::Grpc,
                    "service/Method",
                    body,
                )
                .expect_err("pre-restart token")
                .code,
            ErrorCode::Unauthorized
        );
    }

    #[test]
    fn saturation_never_evicts_unexpired_nonces() {
        let verifier = verifier_at(Arc::new(AtomicU64::new(3_000_000)));
        {
            let mut cache = verifier.replay.lock().expect("cache");
            for value in 0..MAX_REPLAY_ENTRIES {
                let mut nonce = [0_u8; GATEWAY_NONCE_BYTES];
                nonce[..8].copy_from_slice(&(value as u64).to_le_bytes());
                cache.expires_by_nonce.insert(nonce, 3_030_000);
                cache.nonces_by_expiry.insert((3_030_000, nonce));
            }
        }
        let token = verifier
            .attest_exact_request(
                GatewayTransport::Http,
                "POST:/v1/recall",
                b"body",
                [0xff; 16],
            )
            .expect("token");
        assert_eq!(
            verifier
                .verify_exact_request(
                    Some("gateway:test"),
                    Some(&token),
                    GatewayTransport::Http,
                    "POST:/v1/recall",
                    b"body",
                )
                .expect_err("saturation")
                .code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            verifier
                .replay
                .lock()
                .expect("cache")
                .expires_by_nonce
                .len(),
            MAX_REPLAY_ENTRIES
        );
    }

    #[test]
    fn malformed_and_legacy_tokens_are_rejected() {
        let verifier = verifier_at(Arc::new(AtomicU64::new(4_000_000)));
        for token in ["", "not-a-hash", "v1.context-only-token"] {
            assert_eq!(
                verifier
                    .verify_exact_request(
                        Some("gateway:test"),
                        Some(token),
                        GatewayTransport::Http,
                        "POST:/v1/recall",
                        b"body",
                    )
                    .expect_err("malformed token")
                    .code,
                ErrorCode::Unauthorized
            );
        }
    }
}
