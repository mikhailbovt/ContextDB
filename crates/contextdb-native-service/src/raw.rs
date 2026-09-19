//! Bounded exact oracle over accepted originals. The persistent provider keeps
//! this path for conformance; it is not the million-event interactive index.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use contextdb_core::{ContentDigest, OriginalSourceSpan, RawSource, Validate};
use contextdb_index::{match_raw_original, raw_query_terms};
use contextdb_service::{
    Capability, CapturePort, ErrorCode, MaterializeOriginalRequest, MaterializedOriginal,
    RawPageStatus, RawRecallHit, RawRecallPage, RawRecallPort, RawRecallRequest, ServiceError,
    ServiceResult,
};
use contextdb_storage::{ReadSnapshot, ScanPageRequest, SnapshotSelector, StorageEngine};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    NativeService, canonical_digest, decode, decode_hex, digest_bytes, encode, encode_hex,
    exhausted, integrity, keyed_token, require_capability, storage_error,
};

const CURSOR_DOMAIN: &[u8] = b"contextdb/raw-recall-cursor/v1";
const MAX_RECALL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MATERIALIZE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCursor {
    binding: String,
    known_at: u64,
    position: u64,
}

impl RawRecallPort for NativeService {
    fn recall_originals(&self, request: RawRecallRequest) -> ServiceResult<RawRecallPage> {
        self.recall_originals_oracle(request)
    }

    fn materialize_original(
        &self,
        request: MaterializeOriginalRequest,
    ) -> ServiceResult<MaterializedOriginal> {
        require_capability(&request.context, Capability::ReadEvidence)?;
        require_capability(&request.context, Capability::RawEvidence)?;
        if request
            .end
            .checked_sub(request.start)
            .is_none_or(|length| length > MAX_MATERIALIZE_BYTES)
        {
            return Err(super::invalid(
                "original range is reversed or exceeds one MiB",
            ));
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        self.authorized_capture_policy(&snapshot, &request.context, request.event_id)?;
        self.authorize_capture_dependencies(&snapshot, &request.context, request.event_id)?;
        let original = self.load_captured_original(&snapshot, request.event_id)?;
        if original.event.payload.digest() != Some(request.payload_digest) {
            return Err(super::invalid(
                "original payload version differs from the requested digest",
            ));
        }
        let bytes = self.original_range(
            &snapshot,
            &request.context,
            &original.event,
            request.start,
            request.end,
        )?;
        Ok(MaterializedOriginal {
            source: RawSource::from(&original.event),
            span: OriginalSourceSpan {
                event_id: request.event_id,
                payload_digest: request.payload_digest,
                start: request.start,
                end: request.end,
                span_digest: ContentDigest::from_bytes(*blake3::hash(&bytes).as_bytes()),
            },
            bytes,
        })
    }
}

impl NativeService {
    /// Exact, bounded oracle for raw retrieval; independent of all projections.
    ///
    /// This deliberately scans the capture outbox for non-ID routes. A continuation
    /// freezes logical knowledge while each page consults current source policy.
    pub fn recall_originals_oracle(
        &self,
        request: RawRecallRequest,
    ) -> ServiceResult<RawRecallPage> {
        validate_request(&request)?;
        if let Some(receipt) = &request.after_receipt {
            self.resolve_capture_receipt(&request.context, receipt)?;
        }
        let snapshot = self
            .engine
            .begin_read(SnapshotSelector::Latest)
            .map_err(storage_error)?;
        let binding = canonical_digest(&(
            &self.database_id,
            request.context.authorization_binding_digest()?,
            &request.filter,
            &request.text,
            request.known_at,
            &request.after_receipt,
        ))?;
        let mut cursor: RawCursor = if let Some(token) = &request.continuation {
            self.open_private_cursor(CURSOR_DOMAIN, token)?
        } else {
            let (_, state) = self.select_snapshot(
                &snapshot,
                &request.context.request.workspace_id,
                request.known_at,
            )?;
            RawCursor {
                binding: binding.clone(),
                known_at: state.watermarks.journal,
                position: 0,
            }
        };
        if cursor.binding != binding
            || request
                .after_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.workspace_commit > cursor.known_at)
        {
            return Err(invalid_cursor());
        }
        let (global, _) = self.select_snapshot(
            &snapshot,
            &request.context.request.workspace_id,
            Some(cursor.known_at),
        )?;
        let workspace = digest_bytes(request.context.request.workspace_id.as_bytes());
        let prefix = format!("outbox/{workspace}/").into_bytes();
        let direct = !request.filter.event_ids.is_empty();
        let (positions, mut has_more) = if direct {
            let start = usize::try_from(cursor.position).map_err(|_| invalid_cursor())?;
            if start > request.filter.event_ids.len() {
                return Err(invalid_cursor());
            }
            let ids = request
                .filter
                .event_ids
                .iter()
                .enumerate()
                .skip(start)
                .take(request.budget.max_records as usize)
                .map(|(index, id)| (index as u64 + 1, *id))
                .collect::<Vec<_>>();
            let more = start + ids.len() < request.filter.event_ids.len();
            (ids, more)
        } else {
            let mut after = prefix.clone();
            after.extend_from_slice(&cursor.position.to_be_bytes());
            let page = snapshot
                .scan_prefix_page(
                    &self.keyspaces.continuous,
                    ScanPageRequest {
                        prefix: &prefix,
                        start_after: Some(&after),
                        max_entries: request.budget.max_records as usize,
                        max_bytes: 16 * 1024 * 1024,
                    },
                )
                .map_err(storage_error)?;
            let mut positions = Vec::with_capacity(page.entries.len());
            for entry in page.entries {
                let work: super::capture::CaptureWork = decode(&entry.value, "raw capture route")?;
                let mut expected = prefix.clone();
                expected.extend_from_slice(&work.workspace_commit.to_be_bytes());
                if entry.key != expected {
                    return Err(integrity("raw capture route key mismatch"));
                }
                positions.push((work.workspace_commit, work.event_id));
            }
            (positions, page.continuation.is_some())
        };
        let mut hits = Vec::new();
        let mut used_bytes = 0;
        let mut status = RawPageStatus::WorkLimit;
        let start_position = cursor.position;
        for (index, &(position, event_id)) in positions.iter().enumerate() {
            if !direct && position > cursor.known_at {
                has_more = false;
                break;
            }
            let policy = match self.authorized_capture_policy(&snapshot, &request.context, event_id)
            {
                Ok(policy) => policy,
                Err(error)
                    if error.code == ErrorCode::PermissionDenied
                        || (direct && error.code == ErrorCode::NotFound) =>
                {
                    cursor.position = position;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if policy.accepted_global_commit > global {
                cursor.position = position;
                continue;
            }
            match self.authorize_capture_dependencies(&snapshot, &request.context, event_id) {
                Ok(()) => (),
                Err(error) if error.code == ErrorCode::PermissionDenied => {
                    cursor.position = position;
                    continue;
                }
                Err(error) => return Err(error),
            }
            let original = self.load_captured_original(&snapshot, event_id)?;
            let source = RawSource::from(&original.event);
            if !request.filter.matches(&source) {
                cursor.position = position;
                continue;
            }
            let matches = if let Some(query) = &request.text {
                let Some(length) = source.byte_length else {
                    cursor.position = position;
                    continue;
                };
                if length > request.budget.max_payload_bytes - used_bytes {
                    if cursor.position == start_position {
                        return Err(exhausted(
                            "one original exceeds the lexical page byte budget; increase it or use ID/range recall",
                        ));
                    }
                    status = RawPageStatus::ByteLimit;
                    has_more = true;
                    break;
                }
                let bytes =
                    self.original_range(&snapshot, &request.context, &original.event, 0, length)?;
                used_bytes += length;
                let digest = source
                    .payload_digest
                    .ok_or_else(|| integrity("available original digest is absent"))?;
                let result = match_raw_original(event_id, digest, &bytes, query)
                    .map_err(|_| integrity("raw original cannot be matched"))?;
                let Some(matches) = result else {
                    cursor.position = position;
                    continue;
                };
                matches
            } else {
                Vec::new()
            };
            cursor.position = position;
            hits.push(RawRecallHit { source, matches });
            if hits.len() >= request.page_size as usize {
                has_more |= index + 1 < positions.len();
                status = RawPageStatus::PageLimit;
                break;
            }
        }
        if !has_more {
            status = RawPageStatus::Complete;
        }
        let continuation = if has_more {
            Some(self.seal_private_cursor(CURSOR_DOMAIN, &cursor)?)
        } else {
            None
        };
        let snapshot = keyed_token(
            &self.token_key,
            b"contextdb/raw-view/v1",
            &encode(&(&binding, cursor.known_at))?,
        );
        Ok(RawRecallPage {
            hits,
            status,
            snapshot,
            continuation,
        })
    }

    pub(super) fn seal_private_cursor<T: Serialize>(
        &self,
        domain: &[u8],
        value: &T,
    ) -> ServiceResult<String> {
        let key = blake3::derive_key(
            "contextdb native private cursor key v1",
            self.token_key.as_ref(),
        );
        let cipher = XChaCha20Poly1305::new(&Key::from(key));
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| integrity("cursor nonce generation failed"))?;
        let aad = encode(&(&self.database_id, domain))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &encode(value)?,
                    aad: &aad,
                },
            )
            .map_err(|_| integrity("cursor encryption failed"))?;
        Ok(encode_hex(
            &[nonce.as_slice(), ciphertext.as_slice()].concat(),
        ))
    }

    pub(super) fn open_private_cursor<T: DeserializeOwned>(
        &self,
        domain: &[u8],
        token: &str,
    ) -> ServiceResult<T> {
        if token.len() > 8192 {
            return Err(invalid_cursor());
        }
        let bytes = decode_hex(token).ok_or_else(invalid_cursor)?;
        if bytes.len() < 40 {
            return Err(invalid_cursor());
        }
        let nonce: [u8; 24] = bytes[..24].try_into().map_err(|_| invalid_cursor())?;
        let key = blake3::derive_key(
            "contextdb native private cursor key v1",
            self.token_key.as_ref(),
        );
        let cipher = XChaCha20Poly1305::new(&Key::from(key));
        let aad = encode(&(&self.database_id, domain))?;
        let payload = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &bytes[24..],
                    aad: &aad,
                },
            )
            .map_err(|_| invalid_cursor())?;
        serde_json::from_slice(&payload).map_err(|_| invalid_cursor())
    }
}

pub(super) fn validate_request(request: &RawRecallRequest) -> ServiceResult<()> {
    require_capability(&request.context, Capability::Recall)?;
    require_capability(&request.context, Capability::ReadEvidence)?;
    require_capability(&request.context, Capability::RawEvidence)?;
    if request.page_size == 0
        || request.page_size > 256
        || request.budget.max_records == 0
        || request.budget.max_records > 65_536
        || request.budget.max_payload_bytes == 0
        || request.budget.max_payload_bytes > MAX_RECALL_BYTES
        || request.filter.event_ids.len() > 64
    {
        return Err(super::invalid(
            "raw recall budget is outside the supported profile",
        ));
    }
    if let Some(range) = request.filter.recorded_range {
        range
            .validate()
            .map_err(|_| super::invalid("raw recorded-time range is invalid"))?;
    }
    if let Some(query) = &request.text {
        raw_query_terms(query).map_err(|_| {
            super::invalid("raw lexical query is invalid or exceeds its term/byte budget")
        })?;
    }
    Ok(())
}

pub(super) fn invalid_cursor() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidContinuation,
        "raw continuation is invalid or bound to another request",
        false,
    )
}

#[cfg(test)]
mod tests;
