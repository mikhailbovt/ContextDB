//! Exact tokenizer contract used for hard budget enforcement.

use crate::{ContextError, Result};

/// Host-supplied exact token counter for a declared model profile.
///
/// Implementations must count the exact bytes sent through the corresponding
/// model channel. Returning estimates under this trait violates the API contract.
pub trait TokenCounter: std::fmt::Debug + Send + Sync {
    /// Stable tokenizer revision bound into compilation and continuation state.
    fn id(&self) -> &str;

    /// Counts tokens exactly according to this tokenizer revision.
    fn count_tokens(&self, input: &str) -> Result<u32>;
}

/// Dependency-free deterministic reference tokenizer used by the baseline and goldens.
///
/// A token is one maximal Unicode-alphanumeric/underscore run or one other
/// non-whitespace Unicode scalar. This is an exact tokenizer definition, not a
/// claim about any third-party model tokenizer.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceTokenizer;

impl ReferenceTokenizer {
    /// Stable revision of the reference tokenization algorithm.
    pub const ID: &'static str = "contextdb.reference_unicode_tokens.v1";
}

impl TokenCounter for ReferenceTokenizer {
    fn id(&self) -> &str {
        Self::ID
    }

    fn count_tokens(&self, input: &str) -> Result<u32> {
        let mut count = 0_u32;
        let mut in_word = false;
        for character in input.chars() {
            if character.is_alphanumeric() || character == '_' {
                if !in_word {
                    count = count.checked_add(1).ok_or_else(|| {
                        ContextError::Tokenizer("reference token count overflow".to_owned())
                    })?;
                    in_word = true;
                }
            } else {
                in_word = false;
                if !character.is_whitespace() {
                    count = count.checked_add(1).ok_or_else(|| {
                        ContextError::Tokenizer("reference token count overflow".to_owned())
                    })?;
                }
            }
        }
        Ok(count)
    }
}

pub(crate) fn checked_sum(left: u32, right: u32, field: &str) -> Result<u32> {
    left.checked_add(right)
        .ok_or_else(|| ContextError::Tokenizer(format!("{field} token count overflow")))
}
