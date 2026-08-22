//! Model-independent logical types and invariants for ContextDB.
//!
//! This crate deliberately contains no storage, transport, scheduler, or model
//! provider integration.  It is the stable semantic boundary shared by those
//! layers.

#![forbid(unsafe_code)]

mod capability;
mod collections;
mod error;
mod evidence;
mod id;
mod identity;
mod maintenance;
mod memory;
mod mutation;
mod policy;
mod provenance;
mod runtime;
mod semantic;
mod time;

pub use capability::*;
pub use collections::NonEmptyVec;
pub use error::{ValidationError, ValidationResult};
pub use evidence::*;
pub use id::*;
pub use identity::*;
pub use maintenance::*;
pub use memory::*;
pub use mutation::*;
pub use policy::*;
pub use provenance::*;
pub use runtime::*;
pub use semantic::*;
pub use time::*;

/// Validation shared by all externally constructible logical values.
pub trait Validate {
    /// Checks local invariants without consulting storage or external state.
    fn validate(&self) -> ValidationResult;

    /// Validates an owned value and returns it unchanged on success.
    fn validated(self) -> ValidationResult<Self>
    where
        Self: Sized,
    {
        self.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
