//! Owned conversational execution, separate from the database foundation runtime.
//! Originals remain durable; rolling changes only what the reader sees at once.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod fence;
mod model;
mod rolling;
mod runtime;

#[cfg(test)]
mod tests;

pub use fence::*;
pub use model::*;
pub use rolling::*;
pub use runtime::*;

use contextdb_service::{ErrorCode, ServiceError, ServiceResult};

fn invalid(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::InvalidArgument, message, false)
}
fn exhausted(message: &'static str) -> ServiceError {
    ServiceError::new(ErrorCode::BudgetExhausted, message, false)
}
fn context_error(error: contextdb_context::ContextError) -> ServiceError {
    match error {
        contextdb_context::ContextError::BudgetExceeded(_) => {
            exhausted("whole-request budget exhausted")
        }
        _ => invalid("reader protocol or source layout is invalid"),
    }
}
fn charge(budget: &mut contextdb_recall::QueryBudget, work: u64, bytes: u64) -> ServiceResult<()> {
    budget
        .charge(work, bytes)
        .map_err(|_| exhausted("shared runtime allowance exhausted"))
}
