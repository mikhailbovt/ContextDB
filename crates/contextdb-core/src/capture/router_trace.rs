//! Bounded protected metadata; page integrity never establishes source authority.

use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, de::SeqAccess};

use crate::{
    ContentDigest, ContextPackId, ModelCallId, ModelRequestManifest, Validate, ValidationError,
    ValidationResult,
};

/// Supported protected router attachment version.
pub const ROUTER_TRACE_VERSION: u16 = 1;
/// Aggregate unescaped UTF-8 envelope ceiling.
pub const MAX_ROUTER_TRACE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of complete UTF-8 pages.
pub const MAX_ROUTER_TRACE_PAGES: usize = 8;
/// Unescaped UTF-8 page ceiling.
pub const MAX_ROUTER_TRACE_PAGE_BYTES: usize = 256 * 1024;

/// Exact ordered page commitment, retainable independently of its protected text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterTracePageDescriptor {
    /// Contiguous zero-based page position.
    pub index: u32,
    /// Exact unescaped UTF-8 byte length.
    pub byte_length: u32,
    /// BLAKE3 of the unescaped UTF-8 page.
    pub digest: ContentDigest,
}

/// Accepted occurrence and query-time commitments. The owner verifies their
/// semantic association and source controls separately from this local format.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterTraceHeader {
    /// Protected attachment contract version.
    pub version: u16,
    /// Same final call identity as the captured model request.
    pub model_call_id: ModelCallId,
    /// Exact prepared ContextPack identity.
    pub pack_id: ContextPackId,
    /// Exact model wire commitment; pages do not participate in it.
    pub wire_digest: ContentDigest,
    /// Exact model wire length.
    pub wire_byte_length: u64,
    /// Authorized router request commitment.
    pub router_request_digest: ContentDigest,
    /// Accepted router plan commitment.
    pub router_plan_digest: ContentDigest,
    /// Accepted compiler router manifest commitment.
    pub router_manifest_digest: ContentDigest,
    /// Exact owner-resolved complete origin/control union commitment.
    pub origin_closure_digest: ContentDigest,
    /// BLAKE3 of concatenated unescaped UTF-8 page bytes.
    pub trace_digest: ContentDigest,
    /// Exact concatenated unescaped UTF-8 byte length.
    pub byte_length: u32,
    /// Ordered page commitments, with no protected query-time content.
    #[serde(deserialize_with = "bounded_pages")]
    pub pages: Vec<RouterTracePageDescriptor>,
}

impl fmt::Debug for RouterTraceHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterTraceHeader")
            .field("version", &self.version)
            .field("page_count", &self.pages.len())
            .field("byte_length", &self.byte_length)
            .field("trace_digest", &self.trace_digest)
            .field("origin_closure_digest", &self.origin_closure_digest)
            .finish_non_exhaustive()
    }
}

/// One protected UTF-8 page. Neither Debug nor validation errors expose its text.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterTracePage {
    /// Contiguous zero-based page position.
    pub index: u32,
    /// Exact unescaped UTF-8 byte length.
    pub byte_length: u32,
    /// BLAKE3 of this page's unescaped UTF-8 bytes.
    pub digest: ContentDigest,
    /// Sensitive canonical native envelope bytes, never model input.
    #[serde(deserialize_with = "page_text")]
    pub text: String,
}

impl fmt::Debug for RouterTracePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterTracePage")
            .field("index", &self.index)
            .field("byte_length", &self.byte_length)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Inline routing metadata in the same immutable model-request occurrence.
/// It is not an independent source, lease, grant or training permission.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterTraceAttachment {
    /// Immutable occurrence, envelope and origin commitments.
    pub header: RouterTraceHeader,
    /// Complete ordered protected text, with no partial/truncated profile.
    #[serde(deserialize_with = "bounded_pages")]
    pub pages: Vec<RouterTracePage>,
}

impl fmt::Debug for RouterTraceAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterTraceAttachment")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

impl RouterTraceAttachment {
    /// Page an already bounded native canonical envelope at UTF-8 boundaries.
    /// The native owner remains responsible for validating its actual contents.
    #[allow(clippy::too_many_arguments, reason = "explicit occurrence commitments")]
    pub fn new(
        model_call_id: ModelCallId,
        pack_id: ContextPackId,
        wire_digest: ContentDigest,
        wire_byte_length: u64,
        router_request_digest: ContentDigest,
        router_plan_digest: ContentDigest,
        router_manifest_digest: ContentDigest,
        origin_closure_digest: ContentDigest,
        canonical_json: &str,
    ) -> ValidationResult<Self> {
        if canonical_json.is_empty() || canonical_json.len() > MAX_ROUTER_TRACE_BYTES {
            return Err(invalid("router trace envelope exceeds its byte ceiling"));
        }
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < canonical_json.len() {
            if pages.len() >= MAX_ROUTER_TRACE_PAGES {
                return Err(invalid("router trace exceeds its page ceiling"));
            }
            let mut end = (offset + MAX_ROUTER_TRACE_PAGE_BYTES).min(canonical_json.len());
            while !canonical_json.is_char_boundary(end) {
                end -= 1;
            }
            let text = &canonical_json[offset..end];
            pages.push(RouterTracePage {
                index: pages.len() as u32,
                byte_length: text.len() as u32,
                digest: hash(text.as_bytes()),
                text: text.into(),
            });
            offset = end;
        }
        let header = RouterTraceHeader {
            version: ROUTER_TRACE_VERSION,
            model_call_id,
            pack_id,
            wire_digest,
            wire_byte_length,
            router_request_digest,
            router_plan_digest,
            router_manifest_digest,
            origin_closure_digest,
            trace_digest: hash(canonical_json.as_bytes()),
            byte_length: canonical_json.len() as u32,
            pages: pages.iter().map(RouterTracePage::descriptor).collect(),
        };
        Self { header, pages }.validated()
    }

    /// Verify local page integrity and the containing request's call/wire link.
    pub fn validate_for_model_request(&self, manifest: &ModelRequestManifest) -> ValidationResult {
        self.validate()?;
        if self.header.model_call_id != manifest.model_call_id
            || self.header.wire_digest != manifest.wire_digest
            || self.header.wire_byte_length != manifest.byte_length
        {
            return Err(invalid("router trace differs from its model request"));
        }
        Ok(())
    }

    /// Reconstruct the complete bounded envelope after checking every page.
    pub fn canonical_json(&self) -> ValidationResult<String> {
        self.validate()?;
        let mut result = String::with_capacity(self.header.byte_length as usize);
        for page in &self.pages {
            result.push_str(&page.text);
        }
        Ok(result)
    }
}

impl RouterTracePage {
    fn descriptor(&self) -> RouterTracePageDescriptor {
        RouterTracePageDescriptor {
            index: self.index,
            byte_length: self.byte_length,
            digest: self.digest,
        }
    }
}

impl Validate for RouterTraceHeader {
    fn validate(&self) -> ValidationResult {
        if self.version != ROUTER_TRACE_VERSION
            || self.wire_byte_length == 0
            || self.byte_length == 0
            || self.byte_length as usize > MAX_ROUTER_TRACE_BYTES
            || self.pages.is_empty()
            || self.pages.len() > MAX_ROUTER_TRACE_PAGES
        {
            return Err(invalid("unsupported or excessive router trace header"));
        }
        let mut total = 0_u64;
        for (index, page) in self.pages.iter().enumerate() {
            if page.index as usize != index
                || page.byte_length == 0
                || page.byte_length as usize > MAX_ROUTER_TRACE_PAGE_BYTES
            {
                return Err(invalid("invalid router trace page descriptor"));
            }
            total += u64::from(page.byte_length);
        }
        if total != u64::from(self.byte_length) {
            return Err(invalid("router trace page lengths disagree"));
        }
        Ok(())
    }
}

impl Validate for RouterTraceAttachment {
    fn validate(&self) -> ValidationResult {
        self.header.validate()?;
        if self.pages.len() != self.header.pages.len() {
            return Err(invalid("missing or extra router trace pages"));
        }
        let mut hasher = blake3::Hasher::new();
        for (page, descriptor) in self.pages.iter().zip(&self.header.pages) {
            if page.text.is_empty()
                || page.text.len() > MAX_ROUTER_TRACE_PAGE_BYTES
                || page.byte_length as usize != page.text.len()
                || page.descriptor() != *descriptor
                || page.digest != hash(page.text.as_bytes())
            {
                return Err(invalid("router trace page integrity failed"));
            }
            hasher.update(page.text.as_bytes());
        }
        if self.header.trace_digest != ContentDigest::from_bytes(*hasher.finalize().as_bytes()) {
            return Err(invalid("router trace envelope integrity failed"));
        }
        Ok(())
    }
}

fn hash(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn invalid(reason: &'static str) -> ValidationError {
    ValidationError::InvalidState { reason }
}

fn bounded_pages<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    struct Pages<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Pages<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("at most eight complete router trace pages")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut pages = Vec::with_capacity(MAX_ROUTER_TRACE_PAGES);
            for _ in 0..MAX_ROUTER_TRACE_PAGES {
                match sequence.next_element()? {
                    Some(page) => pages.push(page),
                    None => return Ok(pages),
                }
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom(
                    "router trace page ceiling exceeded",
                ));
            }
            Ok(pages)
        }
    }
    deserializer.deserialize_seq(Pages(PhantomData))
}

fn page_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct Text;
    impl serde::de::Visitor<'_> for Text {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a nonempty bounded UTF-8 router trace page")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            if value.is_empty() || value.len() > MAX_ROUTER_TRACE_PAGE_BYTES {
                return Err(E::custom("router trace page byte ceiling exceeded"));
            }
            Ok(value.into())
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
            if value.is_empty() || value.len() > MAX_ROUTER_TRACE_PAGE_BYTES {
                return Err(E::custom("router trace page byte ceiling exceeded"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_string(Text)
}

#[cfg(test)]
mod tests;
