//! Embedded Python facade over the canonical ContextDB service.
//!
//! Python is an adapter only: requests are strict canonical JSON and no
//! Python object receives storage or semantic-mutation authority.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::allow_attributes_without_reason,
    reason = "PyO3 macros emit compatibility attributes"
)]

use contextdb_service::{
    CognitiveMemoryService, ExplainRecallRequest, ExportRequest, ImportRequest, ObserveRequest,
    RecallRequest, ReferenceService, ServiceError, VerifyRequest,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// In-process Python-owned reference ContextDB instance.
#[pyclass(name = "ContextDb")]
#[derive(Debug)]
pub struct PyContextDb {
    service: ReferenceService,
}

#[pymethods]
impl PyContextDb {
    /// Creates an empty instance with a caller-provided 32-byte token key.
    #[new]
    fn new(database_id: String, continuation_key: Vec<u8>) -> PyResult<Self> {
        let key: [u8; 32] = continuation_key
            .try_into()
            .map_err(|_| PyValueError::new_err("continuation_key must contain exactly 32 bytes"))?;
        Ok(Self {
            service: ReferenceService::new(database_id, key).map_err(service_error)?,
        })
    }

    /// Captures one canonical JSON observation and returns canonical JSON.
    fn observe_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.observe(request))
    }

    /// Runs policy-first recall from canonical JSON.
    fn recall_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.recall(request))
    }

    /// Validates and returns a privacy-safe recall trace.
    fn explain_recall_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.explain_recall(request))
    }

    /// Exports a canonical logical archive response as JSON.
    fn export_archive_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.export_archive(request))
    }

    /// Imports a verified canonical logical archive from JSON.
    fn import_archive_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.import_archive(request))
    }

    /// Runs shallow or deep logical verification from canonical JSON.
    fn verify_json(&self, request_json: &str) -> PyResult<String> {
        invoke(request_json, |request| self.service.verify(request))
    }
}

fn invoke<Request, Response, Operation>(
    request_json: &str,
    operation: Operation,
) -> PyResult<String>
where
    Request: DeserializeOwned,
    Response: Serialize,
    Operation: FnOnce(Request) -> Result<Response, ServiceError>,
{
    let request = serde_json::from_str(request_json)
        .map_err(|_| PyValueError::new_err("request is not valid canonical service JSON"))?;
    let response = operation(request).map_err(service_error)?;
    serde_json::to_string(&response)
        .map_err(|_| PyRuntimeError::new_err("response serialization failed"))
}

fn service_error(error: ServiceError) -> PyErr {
    let encoded = serde_json::to_string(&error).unwrap_or_else(|_| {
        "{\"code\":\"unavailable\",\"message\":\"error serialization failed\",\"retryable\":true}".to_owned()
    });
    PyRuntimeError::new_err(encoded)
}

/// Native module exported by maturin as `contextdb_embedded._contextdb`.
#[pymodule]
fn _contextdb(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyContextDb>()?;
    Ok(())
}

// Keep request types concretely reachable so the generic method inference is
// stable across PyO3 macro expansion and future compiler changes.
const _: fn(&PyContextDb, &str) -> PyResult<String> =
    |db, json| invoke::<ObserveRequest, _, _>(json, |request| db.service.observe(request));
const _: fn(&PyContextDb, &str) -> PyResult<String> =
    |db, json| invoke::<RecallRequest, _, _>(json, |request| db.service.recall(request));
const _: fn(&PyContextDb, &str) -> PyResult<String> = |db, json| {
    invoke::<ExplainRecallRequest, _, _>(json, |request| db.service.explain_recall(request))
};
const _: fn(&PyContextDb, &str) -> PyResult<String> =
    |db, json| invoke::<ExportRequest, _, _>(json, |request| db.service.export_archive(request));
const _: fn(&PyContextDb, &str) -> PyResult<String> =
    |db, json| invoke::<ImportRequest, _, _>(json, |request| db.service.import_archive(request));
const _: fn(&PyContextDb, &str) -> PyResult<String> =
    |db, json| invoke::<VerifyRequest, _, _>(json, |request| db.service.verify(request));

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use contextdb_service::{
        AccessPolicy, Consent, ObserveRequest, RequestContext, Sensitivity, VerifyRequest,
    };

    use super::PyContextDb;

    fn admin() -> RequestContext {
        RequestContext {
            request_id: "python:test".into(),
            workspace_id: "workspace:python".into(),
            subject_id: "subject:admin".into(),
            audiences: BTreeSet::new(),
            scopes: BTreeSet::new(),
            purpose: "contextdb:admin".into(),
            clearance: Sensitivity::Restricted,
        }
    }

    #[test]
    fn binding_uses_exact_service_json_and_preserves_replay() {
        let database = PyContextDb::new("python-test".into(), vec![23; 32]).expect("database");
        let request = ObserveRequest {
            context: RequestContext {
                request_id: "python:observe".into(),
                workspace_id: "workspace:python".into(),
                subject_id: "subject:alice".into(),
                audiences: BTreeSet::from(["subject:alice".into()]),
                scopes: BTreeSet::from(["project:python".into()]),
                purpose: "assist".into(),
                clearance: Sensitivity::Private,
            },
            idempotency_key: "idempotency:python".into(),
            observation_id: "observation:python".into(),
            metadata: BTreeMap::new(),
            content: serde_json::json!({"text": "native binding"}),
            access: AccessPolicy {
                workspace_id: "workspace:python".into(),
                scopes: BTreeSet::from(["project:python".into()]),
                owners: BTreeSet::from(["subject:alice".into()]),
                audience: BTreeSet::from(["subject:alice".into()]),
                audience_purpose_grants: BTreeMap::new(),
                purposes: BTreeSet::from(["assist".into()]),
                sensitivity: Sensitivity::Private,
                consent: Consent::Granted,
                retrievable: true,
            },
        };
        let json = serde_json::to_string(&request).expect("JSON");
        let first: serde_json::Value =
            serde_json::from_str(&database.observe_json(&json).expect("first observation"))
                .expect("response JSON");
        let replay: serde_json::Value =
            serde_json::from_str(&database.observe_json(&json).expect("replayed observation"))
                .expect("response JSON");
        assert_eq!(first["commit_seq"], replay["commit_seq"]);
        assert_eq!(replay["replayed"], true);

        let verify = serde_json::to_string(&VerifyRequest {
            context: admin(),
            deep: true,
        })
        .expect("JSON");
        let verified: serde_json::Value =
            serde_json::from_str(&database.verify_json(&verify).expect("verify"))
                .expect("response JSON");
        assert_eq!(verified["valid"], true);
    }
}
