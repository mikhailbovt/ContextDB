use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{ErrorCode, RecallRequest, ServiceError, ServiceResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageCursor {
    pub(crate) schema_version: u16,
    pub(crate) request_digest: String,
    pub(crate) snapshot_seq: u64,
    pub(crate) offset: u64,
}

pub(crate) fn request_digest(request: &RecallRequest) -> ServiceResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        schema_version: u16,
        workspace_id: &'a str,
        subject_id: &'a str,
        audiences: &'a std::collections::BTreeSet<String>,
        scopes: &'a std::collections::BTreeSet<String>,
        purpose: &'a str,
        clearance: crate::Sensitivity,
        query: &'a str,
        page_size: u32,
    }
    digest_json(&Binding {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        workspace_id: &request.context.workspace_id,
        subject_id: &request.context.subject_id,
        audiences: &request.context.audiences,
        scopes: &request.context.scopes,
        purpose: &request.context.purpose,
        clearance: request.context.clearance,
        query: &request.query,
        page_size: request.page_size,
    })
}

pub(crate) fn encode(
    key: &[u8; 32],
    request_digest: String,
    snapshot_seq: u64,
    offset: u64,
) -> ServiceResult<String> {
    let cursor = PageCursor {
        schema_version: crate::SERVICE_SCHEMA_VERSION,
        request_digest,
        snapshot_seq,
        offset,
    };
    encode_value(key, &cursor)
}

pub(crate) fn decode(key: &[u8; 32], token: &str) -> ServiceResult<PageCursor> {
    let cursor: PageCursor = decode_value(key, token)?;
    if cursor.schema_version != crate::SERVICE_SCHEMA_VERSION || cursor.offset > 100_000 {
        return Err(invalid_token());
    }
    Ok(cursor)
}

pub(crate) fn encode_value<T: Serialize>(key: &[u8; 32], value: &T) -> ServiceResult<String> {
    let payload = serde_json::to_vec(value).map_err(serialization_error)?;
    let mac = blake3::keyed_hash(key, &payload);
    Ok(format!("{}.{}", hex_encode(&payload), mac.to_hex()))
}

pub(crate) fn decode_value<T: DeserializeOwned>(key: &[u8; 32], token: &str) -> ServiceResult<T> {
    if token.len() > 8_192 {
        return Err(invalid_token());
    }
    let (payload, claimed_mac) = token.split_once('.').ok_or_else(invalid_token)?;
    let payload = hex_decode(payload)?;
    let claimed_mac = hex_decode(claimed_mac)?;
    if claimed_mac.len() != blake3::OUT_LEN {
        return Err(invalid_token());
    }
    let actual_mac = blake3::keyed_hash(key, &payload);
    // `blake3::Hash` implements constant-time equality against byte slices.
    // Keep the hash on the left: slice-to-slice equality is not constant-time.
    if actual_mac != *claimed_mac.as_slice() {
        return Err(invalid_token());
    }
    serde_json::from_slice(&payload).map_err(|_| invalid_token())
}

pub(crate) fn digest_value<T: Serialize>(value: &T) -> ServiceResult<String> {
    digest_json(value)
}

pub(crate) fn trace_id<T: Serialize>(key: &[u8; 32], value: &T) -> ServiceResult<String> {
    let bytes = serde_json::to_vec(value).map_err(serialization_error)?;
    Ok(blake3::keyed_hash(key, &bytes).to_hex().to_string())
}

fn digest_json<T: Serialize>(value: &T) -> ServiceResult<String> {
    let bytes = serde_json::to_vec(value).map_err(serialization_error)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> ServiceResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(invalid_token());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let encoded = std::str::from_utf8(chunk).map_err(|_| invalid_token())?;
            u8::from_str_radix(encoded, 16).map_err(|_| invalid_token())
        })
        .collect()
}

fn serialization_error(_: serde_json::Error) -> ServiceError {
    ServiceError::new(
        ErrorCode::IntegrityFailure,
        "canonical service serialization failed",
        false,
    )
}

fn invalid_token() -> ServiceError {
    ServiceError::new(
        ErrorCode::InvalidContinuation,
        "continuation is invalid or bound to another request",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{decode_value, encode_value};
    use crate::ErrorCode;

    #[test]
    fn signed_token_rejects_mac_length_changes_and_bit_flips() {
        let key = [9_u8; 32];
        let token = encode_value(&key, &vec!["bound", "state"]).expect("encode");
        let (payload, mac) = token.split_once('.').expect("token shape");

        for malformed_mac in [
            &mac[..mac.len().saturating_sub(2)],
            &format!("{mac}00"),
            "00",
        ] {
            let malformed = format!("{payload}.{malformed_mac}");
            assert_eq!(
                decode_value::<Vec<String>>(&key, &malformed)
                    .expect_err("MAC length must be exact")
                    .code,
                ErrorCode::InvalidContinuation
            );
        }

        let mut flipped = mac.as_bytes().to_vec();
        flipped[0] = if flipped[0] == b'0' { b'1' } else { b'0' };
        let flipped = String::from_utf8(flipped).expect("hex remains UTF-8");
        assert_eq!(
            decode_value::<Vec<String>>(&key, &format!("{payload}.{flipped}"))
                .expect_err("bit flip must fail")
                .code,
            ErrorCode::InvalidContinuation
        );
    }

    #[test]
    fn signed_token_preserves_the_total_input_budget() {
        let oversized = "0".repeat(8_193);
        assert_eq!(
            decode_value::<Vec<String>>(&[1_u8; 32], &oversized)
                .expect_err("oversized token")
                .code,
            ErrorCode::InvalidContinuation
        );
    }
}
