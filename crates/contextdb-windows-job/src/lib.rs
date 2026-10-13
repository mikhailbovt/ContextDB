//! Windows-only owned process lifetime boundary for the local encoder.
//!
//! The rest of ContextDB forbids unsafe code. This crate isolates the generated
//! Win32 bindings behind a safe API that can control only processes it creates.

#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Generated Win32 calls are confined to this owned-process boundary; handles and pointer lifetimes are checked locally"
)]
mod windows;

#[cfg(windows)]
pub use windows::JobChild;
