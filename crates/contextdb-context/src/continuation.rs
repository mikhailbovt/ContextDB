//! Opaque, keyed, snapshot/filter/profile-bound progressive-pack continuation.

use crate::{
    CONTEXT_COMPILER_VERSION, CompileRequest, ContextContinuationToken, ContextError, Result,
};

const MAGIC: &[u8; 4] = b"CTP1";
const BODY_LEN: usize = 4 + 8 + 4 + 8 + 8 + 8 + (32 * 5);
const TOKEN_LEN: usize = BODY_LEN + 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ContinuationState {
    pub next_offset: u32,
    pub cumulative_tokens: u64,
    pub cumulative_blocks: u64,
    pub cumulative_evidence: u64,
    pub chain_digest: [u8; 32],
}

pub(crate) fn issue(
    key: &[u8; 32],
    request: &CompileRequest,
    state: ContinuationState,
) -> Result<ContextContinuationToken> {
    let mut body = Vec::with_capacity(BODY_LEN);
    body.extend_from_slice(MAGIC);
    body.extend_from_slice(&request.snapshot.commit_seq.to_le_bytes());
    body.extend_from_slice(&state.next_offset.to_le_bytes());
    body.extend_from_slice(&state.cumulative_tokens.to_le_bytes());
    body.extend_from_slice(&state.cumulative_blocks.to_le_bytes());
    body.extend_from_slice(&state.cumulative_evidence.to_le_bytes());
    body.extend_from_slice(snapshot_digest(request)?.as_bytes());
    body.extend_from_slice(blake3::hash(request.filter_digest.as_bytes()).as_bytes());
    body.extend_from_slice(profile_digest(request)?.as_bytes());
    body.extend_from_slice(blake3::hash(CONTEXT_COMPILER_VERSION.as_bytes()).as_bytes());
    body.extend_from_slice(&state.chain_digest);
    debug_assert_eq!(body.len(), BODY_LEN);
    let mac = blake3::keyed_hash(key, &body);
    body.extend_from_slice(mac.as_bytes());
    Ok(ContextContinuationToken {
        opaque: encode_hex(&body),
    })
}

pub(crate) fn verify(
    key: &[u8; 32],
    request: &CompileRequest,
    token: &ContextContinuationToken,
) -> Result<ContinuationState> {
    let bytes = decode_hex(&token.opaque)?;
    if bytes.len() != TOKEN_LEN || bytes.get(..4) != Some(MAGIC) {
        return Err(ContextError::InvalidContinuation(
            "unsupported continuation framing".to_owned(),
        ));
    }
    let (body, supplied_mac) = bytes.split_at(BODY_LEN);
    let expected_mac = blake3::keyed_hash(key, body);
    if !constant_time_equal(supplied_mac, expected_mac.as_bytes()) {
        return Err(ContextError::InvalidContinuation(
            "continuation authentication failed".to_owned(),
        ));
    }

    let commit_seq = read_u64(body, 4)?;
    let next_offset = read_u32(body, 12)?;
    let cumulative_tokens = read_u64(body, 16)?;
    let cumulative_blocks = read_u64(body, 24)?;
    let cumulative_evidence = read_u64(body, 32)?;
    if commit_seq != request.snapshot.commit_seq {
        return Err(ContextError::InvalidContinuation(
            "continuation belongs to another commit snapshot".to_owned(),
        ));
    }
    let snapshot = snapshot_digest(request)?;
    let filter = blake3::hash(request.filter_digest.as_bytes());
    let profile = profile_digest(request)?;
    let compiler = blake3::hash(CONTEXT_COMPILER_VERSION.as_bytes());
    if body.get(40..72) != Some(snapshot.as_bytes())
        || body.get(72..104) != Some(filter.as_bytes())
        || body.get(104..136) != Some(profile.as_bytes())
        || body.get(136..168) != Some(compiler.as_bytes())
    {
        return Err(ContextError::InvalidContinuation(
            "continuation snapshot/filter/profile/compiler binding differs".to_owned(),
        ));
    }
    let chain_slice = body.get(168..200).ok_or_else(|| {
        ContextError::InvalidContinuation("continuation chain digest is truncated".to_owned())
    })?;
    let mut chain_digest = [0_u8; 32];
    chain_digest.copy_from_slice(chain_slice);
    Ok(ContinuationState {
        next_offset,
        cumulative_tokens,
        cumulative_blocks,
        cumulative_evidence,
        chain_digest,
    })
}

fn snapshot_digest(request: &CompileRequest) -> Result<blake3::Hash> {
    let bytes = serde_json::to_vec(&request.snapshot)
        .map_err(|error| ContextError::Serialization(error.to_string()))?;
    Ok(blake3::hash(&bytes))
}

fn profile_digest(request: &CompileRequest) -> Result<blake3::Hash> {
    let bytes = serde_json::to_vec(&(
        &request.model_profile,
        request.purpose,
        &request.scopes,
        request.temporal_view,
        &request.required_facets,
        request.budgets,
        request.explicit_memory_request,
        request.require_primary_evidence,
    ))
    .map_err(|error| ContextError::Serialization(error.to_string()))?;
    Ok(blake3::hash(&bytes))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| {
        ContextError::InvalidContinuation("continuation integer is truncated".to_owned())
    })?;
    let mut array = [0_u8; 4];
    array.copy_from_slice(value);
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| {
        ContextError::InvalidContinuation("continuation integer is truncated".to_owned())
    })?;
    let mut array = [0_u8; 8];
    array.copy_from_slice(value);
    Ok(u64::from_le_bytes(array))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.is_empty() {
        return Err(ContextError::InvalidContinuation(
            "continuation is not canonical hexadecimal".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ContextError::InvalidContinuation(
            "continuation is not lowercase canonical hexadecimal".to_owned(),
        )),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
