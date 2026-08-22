use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ConformanceError, ConformanceResult};

/// Stable Protobuf field identity bound to a permanent field number.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSignature {
    /// Field name.
    pub name: String,
    /// Declared scalar/message/enum type.
    pub type_name: String,
    /// `singular`, `optional`, `repeated`, or `oneof:<name>`.
    pub cardinality: String,
}

/// Stable RPC method signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSignature {
    /// Request message type.
    pub request: String,
    /// Response message type.
    pub response: String,
    /// Client-streaming flag.
    pub client_streaming: bool,
    /// Server-streaming flag.
    pub server_streaming: bool,
}

/// Canonical public schema snapshot used as the compatibility oracle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaManifest {
    /// Protobuf package.
    pub package: String,
    /// Enum name -> numeric value -> stable symbolic name.
    pub enums: BTreeMap<String, BTreeMap<u32, String>>,
    /// Message name -> field number -> field signature.
    pub messages: BTreeMap<String, BTreeMap<u32, FieldSignature>>,
    /// Service name -> method name -> RPC signature.
    pub services: BTreeMap<String, BTreeMap<String, RpcSignature>>,
}

/// Additive-compatibility result. Violations are stable and sorted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaCompatibilityReport {
    /// True when every baseline identity/signature remains intact.
    pub compatible: bool,
    /// Number of new enum values, fields, and RPCs.
    pub additive_items: u64,
    /// Stable violations.
    pub violations: Vec<String>,
}

/// Parses the constrained canonical `.proto` grammar into a stable manifest.
/// Unsupported constructs fail rather than being silently omitted.
pub fn parse_proto_schema(source: &str) -> ConformanceResult<SchemaManifest> {
    #[derive(Debug)]
    enum Block {
        Enum(String),
        Message { name: String, oneof: Option<String> },
        Service(String),
    }

    let mut manifest = SchemaManifest {
        package: String::new(),
        enums: BTreeMap::new(),
        messages: BTreeMap::new(),
        services: BTreeMap::new(),
    };
    let mut block: Option<Block> = None;
    for (offset, raw) in source.lines().enumerate() {
        let line_number = offset.saturating_add(1);
        let line = raw.split("//").next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with("syntax ") {
            continue;
        }
        if block.is_none() {
            if let Some(package) = line
                .strip_prefix("package ")
                .and_then(|value| value.strip_suffix(';'))
            {
                manifest.package = package.trim().to_owned();
            } else if let Some(name) = block_name(line, "enum") {
                manifest.enums.entry(name.clone()).or_default();
                block = Some(Block::Enum(name));
            } else if let Some(name) = block_name(line, "message") {
                manifest.messages.entry(name.clone()).or_default();
                block = Some(Block::Message { name, oneof: None });
            } else if let Some(name) = block_name(line, "service") {
                manifest.services.entry(name.clone()).or_default();
                block = Some(Block::Service(name));
            }
            continue;
        }

        let Some(current) = block.as_mut() else {
            continue;
        };
        match current {
            Block::Enum(name) => {
                if line == "}" {
                    block = None;
                } else if !line.starts_with("reserved ") {
                    let (symbol, number) = parse_assignment(line, line_number)?;
                    let values = manifest.enums.get_mut(name).ok_or_else(|| {
                        ConformanceError::Protocol("enum parser state is invalid".to_owned())
                    })?;
                    if values.insert(number, symbol).is_some() {
                        return Err(schema_error(line_number, "duplicate enum number"));
                    }
                }
            }
            Block::Message { name, oneof } => {
                if line == "}" {
                    if oneof.take().is_none() {
                        block = None;
                    }
                } else if let Some(group) = block_name(line, "oneof") {
                    if oneof.replace(group).is_some() {
                        return Err(schema_error(line_number, "nested oneof is unsupported"));
                    }
                } else if !line.starts_with("reserved ") {
                    let (number, signature) = parse_field(line, oneof.as_deref(), line_number)?;
                    let fields = manifest.messages.get_mut(name).ok_or_else(|| {
                        ConformanceError::Protocol("message parser state is invalid".to_owned())
                    })?;
                    if fields.insert(number, signature).is_some() {
                        return Err(schema_error(line_number, "duplicate field number"));
                    }
                }
            }
            Block::Service(name) => {
                if line == "}" {
                    block = None;
                } else {
                    let (method, signature) = parse_rpc(line, line_number)?;
                    let methods = manifest.services.get_mut(name).ok_or_else(|| {
                        ConformanceError::Protocol("service parser state is invalid".to_owned())
                    })?;
                    if methods.insert(method, signature).is_some() {
                        return Err(schema_error(line_number, "duplicate RPC method"));
                    }
                }
            }
        }
    }
    if block.is_some() || manifest.package.is_empty() {
        return Err(ConformanceError::Protocol(
            "schema is incomplete or package is missing".to_owned(),
        ));
    }
    Ok(manifest)
}

/// Parses the checked-in canonical v1 schema.
pub fn current_schema_manifest() -> ConformanceResult<SchemaManifest> {
    parse_proto_schema(include_str!(
        "../../contextdb-proto/proto/contextdb/v1/contextdb.proto"
    ))
}

/// Compares a candidate to a released baseline. New items are additive; any
/// removed, renumbered, renamed, or retyped baseline item is incompatible.
#[must_use]
pub fn compare_schema_compatibility(
    baseline: &SchemaManifest,
    candidate: &SchemaManifest,
) -> SchemaCompatibilityReport {
    let mut violations = Vec::new();
    let mut additive_items = 0_u64;
    if baseline.package != candidate.package {
        violations.push(format!(
            "package changed from {} to {}",
            baseline.package, candidate.package
        ));
    }
    compare_numbered(
        "enum",
        &baseline.enums,
        &candidate.enums,
        &mut additive_items,
        &mut violations,
    );
    compare_numbered(
        "message",
        &baseline.messages,
        &candidate.messages,
        &mut additive_items,
        &mut violations,
    );
    for (service, baseline_methods) in &baseline.services {
        let Some(candidate_methods) = candidate.services.get(service) else {
            violations.push(format!("service {service} was removed"));
            continue;
        };
        for (method, signature) in baseline_methods {
            match candidate_methods.get(method) {
                Some(candidate_signature) if candidate_signature == signature => {}
                Some(candidate_signature) => violations.push(format!(
                    "rpc {service}.{method} changed from {signature:?} to {candidate_signature:?}"
                )),
                None => violations.push(format!("rpc {service}.{method} was removed")),
            }
        }
        additive_items = additive_items.saturating_add(
            u64::try_from(
                candidate_methods
                    .len()
                    .saturating_sub(baseline_methods.len()),
            )
            .unwrap_or(u64::MAX),
        );
    }
    for (service, methods) in &candidate.services {
        if !baseline.services.contains_key(service) {
            additive_items =
                additive_items.saturating_add(u64::try_from(methods.len()).unwrap_or(u64::MAX));
        }
    }
    violations.sort();
    SchemaCompatibilityReport {
        compatible: violations.is_empty(),
        additive_items,
        violations,
    }
}

fn block_name(line: &str, keyword: &str) -> Option<String> {
    line.strip_prefix(keyword)
        .and_then(|rest| rest.trim().strip_suffix('{'))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn parse_assignment(line: &str, line_number: usize) -> ConformanceResult<(String, u32)> {
    let (name, raw_number) = line
        .strip_suffix(';')
        .and_then(|value| value.split_once('='))
        .ok_or_else(|| schema_error(line_number, "invalid numeric assignment"))?;
    let number = raw_number
        .trim()
        .parse::<u32>()
        .map_err(|_| schema_error(line_number, "invalid numeric value"))?;
    Ok((name.trim().to_owned(), number))
}

fn parse_field(
    line: &str,
    oneof: Option<&str>,
    line_number: usize,
) -> ConformanceResult<(u32, FieldSignature)> {
    let (left, raw_number) = line
        .strip_suffix(';')
        .and_then(|value| value.split_once('='))
        .ok_or_else(|| schema_error(line_number, "invalid field declaration"))?;
    let number_text = raw_number.split_whitespace().next().unwrap_or_default();
    let number = number_text
        .parse::<u32>()
        .map_err(|_| schema_error(line_number, "invalid field number"))?;
    let tokens = left.split_whitespace().collect::<Vec<_>>();
    let (cardinality, type_name, name) = match (oneof, tokens.as_slice()) {
        (Some(group), [type_name, name]) => {
            (format!("oneof:{group}"), (*type_name).to_owned(), *name)
        }
        (None, [label @ ("optional" | "repeated"), type_name, name]) => {
            ((*label).to_owned(), (*type_name).to_owned(), *name)
        }
        (None, [type_name, name]) => ("singular".to_owned(), (*type_name).to_owned(), *name),
        (None, tokens) if tokens.len() >= 3 && tokens[0].starts_with("map<") => {
            let (name, type_tokens) = tokens
                .split_last()
                .ok_or_else(|| schema_error(line_number, "map field declaration is empty"))?;
            let type_name = type_tokens.concat();
            if !type_name.ends_with('>') {
                return Err(schema_error(line_number, "map field type is not closed"));
            }
            ("singular".to_owned(), type_name, *name)
        }
        _ => return Err(schema_error(line_number, "unsupported field declaration")),
    };
    Ok((
        number,
        FieldSignature {
            name: name.to_owned(),
            type_name,
            cardinality,
        },
    ))
}

fn parse_rpc(line: &str, line_number: usize) -> ConformanceResult<(String, RpcSignature)> {
    let value = line
        .strip_prefix("rpc ")
        .and_then(|value| value.strip_suffix(';'))
        .ok_or_else(|| schema_error(line_number, "invalid RPC declaration"))?;
    let (method, rest) = value
        .split_once('(')
        .ok_or_else(|| schema_error(line_number, "RPC request is missing"))?;
    let (request, rest) = rest
        .split_once(')')
        .ok_or_else(|| schema_error(line_number, "RPC request is not closed"))?;
    let response = rest
        .trim()
        .strip_prefix("returns (")
        .and_then(|value| value.strip_suffix(')'))
        .ok_or_else(|| schema_error(line_number, "RPC response is invalid"))?;
    let (client_streaming, request) = strip_stream(request.trim());
    let (server_streaming, response) = strip_stream(response.trim());
    Ok((
        method.trim().to_owned(),
        RpcSignature {
            request: request.to_owned(),
            response: response.to_owned(),
            client_streaming,
            server_streaming,
        },
    ))
}

fn strip_stream(value: &str) -> (bool, &str) {
    value
        .strip_prefix("stream ")
        .map_or((false, value), |value| (true, value.trim()))
}

fn compare_numbered<T: Eq + std::fmt::Debug>(
    kind: &str,
    baseline: &BTreeMap<String, BTreeMap<u32, T>>,
    candidate: &BTreeMap<String, BTreeMap<u32, T>>,
    additive_items: &mut u64,
    violations: &mut Vec<String>,
) {
    for (name, baseline_items) in baseline {
        let Some(candidate_items) = candidate.get(name) else {
            violations.push(format!("{kind} {name} was removed"));
            continue;
        };
        for (number, signature) in baseline_items {
            match candidate_items.get(number) {
                Some(candidate_signature) if candidate_signature == signature => {}
                Some(candidate_signature) => violations.push(format!(
                    "{kind} {name} number {number} changed from {signature:?} to {candidate_signature:?}"
                )),
                None => violations.push(format!("{kind} {name} number {number} was removed")),
            }
        }
        *additive_items = additive_items.saturating_add(
            u64::try_from(candidate_items.len().saturating_sub(baseline_items.len()))
                .unwrap_or(u64::MAX),
        );
    }
    for (name, items) in candidate {
        if !baseline.contains_key(name) {
            *additive_items =
                additive_items.saturating_add(u64::try_from(items.len()).unwrap_or(u64::MAX));
        }
    }
}

fn schema_error(line: usize, message: &str) -> ConformanceError {
    ConformanceError::Protocol(format!("schema line {line}: {message}"))
}
