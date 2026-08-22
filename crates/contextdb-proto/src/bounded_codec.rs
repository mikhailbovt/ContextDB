//! Allocation-bounded Prost codec used by every generated gRPC method.

use std::marker::PhantomData;
use std::sync::OnceLock;

use prost::bytes::Buf;
use prost::{Message, Name};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorSet};
use tonic::Status;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WIRE_FIELDS: usize = 16_384;
const MAX_WIRE_RECURSION: usize = 16;
const MAX_DESCRIPTOR_LOOKUPS: usize = 262_144;
const MAX_DESCRIPTOR_FIELDS_PER_MESSAGE: usize = 128;
const MAX_DESCRIPTOR_ONEOFS_PER_MESSAGE: usize = 16;
const MAX_DESCRIPTOR_MESSAGE_TYPES: usize = 256;
const DEFAULT_REPEATED_ITEMS: usize = 4_096;
const MAX_CANONICAL_CONTEXT_PACK_SECTIONS: usize = 17;
const MAX_GATEWAY_ID_BYTES: usize = 1_024;
const MAX_GATEWAY_ATTESTATION_BYTES: usize = 224;

/// Prost codec which performs a descriptor-driven, allocation-free wire walk
/// before Prost is allowed to materialize any request or response collection.
#[derive(Clone, Debug)]
pub struct BoundedProstCodec<T, U> {
    marker: PhantomData<(T, U)>,
}

impl<T, U> Default for BoundedProstCodec<T, U> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<T, U> Codec for BoundedProstCodec<T, U>
where
    T: Message + Send + 'static,
    U: Message + Name + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = BoundedProstEncoder<T>;
    type Decoder = BoundedProstDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        BoundedProstEncoder::default()
    }

    fn decoder(&mut self) -> Self::Decoder {
        BoundedProstDecoder::default()
    }
}

/// Ordinary Prost encoder paired with [`BoundedProstDecoder`].
#[derive(Clone, Debug)]
pub struct BoundedProstEncoder<T> {
    marker: PhantomData<T>,
    settings: BufferSettings,
}

impl<T> Default for BoundedProstEncoder<T> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
            settings: BufferSettings::default(),
        }
    }
}

impl<T: Message> Encoder for BoundedProstEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, buffer: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(buffer)
            .map_err(|error| Status::internal(format!("protobuf encoding failed: {error}")))
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.settings
    }
}

/// Descriptor-driven decoder that rejects allocation-amplifying wire shapes.
#[derive(Clone, Debug)]
pub struct BoundedProstDecoder<T> {
    marker: PhantomData<T>,
    settings: BufferSettings,
}

impl<T> Default for BoundedProstDecoder<T> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
            settings: BufferSettings::default(),
        }
    }
}

impl<T> Decoder for BoundedProstDecoder<T>
where
    T: Message + Name + Default,
{
    type Item = T;
    type Error = Status;

    fn decode(&mut self, buffer: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        if buffer.remaining() > MAX_MESSAGE_BYTES {
            return Err(resource_exhausted(
                "protobuf message exceeds the wire byte budget",
            ));
        }
        let bytes = buffer.chunk();
        if bytes.len() != buffer.remaining() {
            return Err(resource_exhausted(
                "protobuf decoder input is not a single bounded buffer",
            ));
        }
        admit_wire_message(T::PACKAGE, T::NAME, bytes)?;
        T::decode(buffer)
            .map(Some)
            .map_err(|error| Status::invalid_argument(format!("invalid protobuf message: {error}")))
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.settings
    }
}

#[derive(Debug)]
struct WireBudget {
    fields_left: usize,
    descriptor_lookups_left: usize,
}

fn admit_wire_message(package: &str, name: &str, bytes: &[u8]) -> Result<(), Status> {
    let descriptor_set = descriptor_set()?;
    let descriptor = find_top_level_message(descriptor_set, package, name)
        .ok_or_else(|| Status::failed_precondition("protobuf input type has no wire budget"))?;
    let mut budget = WireBudget {
        fields_left: MAX_WIRE_FIELDS,
        descriptor_lookups_left: MAX_DESCRIPTOR_LOOKUPS,
    };
    scan_message(descriptor_set, descriptor, bytes, 0, &mut budget)
}

fn descriptor_set() -> Result<&'static FileDescriptorSet, Status> {
    static DESCRIPTORS: OnceLock<Result<FileDescriptorSet, String>> = OnceLock::new();
    DESCRIPTORS
        .get_or_init(|| {
            FileDescriptorSet::decode(crate::v1::FILE_DESCRIPTOR_SET)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|_| Status::internal("canonical protobuf descriptor set is invalid"))
}

fn find_top_level_message<'a>(
    descriptors: &'a FileDescriptorSet,
    package: &str,
    name: &str,
) -> Option<&'a DescriptorProto> {
    descriptors.file.iter().find_map(|file| {
        (file.package.as_deref().unwrap_or_default() == package)
            .then(|| {
                file.message_type
                    .iter()
                    .find(|message| message.name.as_deref() == Some(name))
            })
            .flatten()
    })
}

fn find_message_by_type_name<'a>(
    descriptors: &'a FileDescriptorSet,
    type_name: &str,
) -> Option<&'a DescriptorProto> {
    let canonical = type_name.strip_prefix('.').unwrap_or(type_name);
    descriptors.file.iter().find_map(|file| {
        let package = file.package.as_deref().unwrap_or_default();
        let relative = canonical
            .strip_prefix(package)
            .and_then(|value| value.strip_prefix('.'))?;
        find_relative_message(&file.message_type, relative)
    })
}

fn find_relative_message<'a>(
    messages: &'a [DescriptorProto],
    relative: &str,
) -> Option<&'a DescriptorProto> {
    let (head, tail) = relative
        .split_once('.')
        .map_or((relative, None), |(head, tail)| (head, Some(tail)));
    let message = messages
        .iter()
        .find(|message| message.name.as_deref() == Some(head))?;
    tail.map_or(Some(message), |tail| {
        find_relative_message(&message.nested_type, tail)
    })
}

fn scan_message(
    descriptors: &FileDescriptorSet,
    message: &DescriptorProto,
    mut bytes: &[u8],
    depth: usize,
    budget: &mut WireBudget,
) -> Result<(), Status> {
    if depth > MAX_WIRE_RECURSION {
        return Err(resource_exhausted(
            "protobuf nesting exceeds the wire budget",
        ));
    }
    if message.field.len() > MAX_DESCRIPTOR_FIELDS_PER_MESSAGE
        || message.oneof_decl.len() > MAX_DESCRIPTOR_ONEOFS_PER_MESSAGE
    {
        return Err(Status::failed_precondition(
            "protobuf message descriptor exceeds the static wire budget",
        ));
    }
    if bytes.is_empty() {
        return Ok(());
    }
    let mut field_counts = [0_usize; MAX_DESCRIPTOR_FIELDS_PER_MESSAGE];
    let mut oneof_counts = [0_usize; MAX_DESCRIPTOR_ONEOFS_PER_MESSAGE];
    let mut nested_descriptors = [None; MAX_DESCRIPTOR_FIELDS_PER_MESSAGE];
    while !bytes.is_empty() {
        budget.fields_left = budget
            .fields_left
            .checked_sub(1)
            .ok_or_else(|| resource_exhausted("protobuf field count exceeds the wire budget"))?;
        let key = read_varint(&mut bytes)?;
        let field_number = u32::try_from(key >> 3)
            .map_err(|_| Status::invalid_argument("protobuf field number is invalid"))?;
        let wire_type = (key & 0x07) as u8;
        if field_number == 0 {
            return Err(Status::invalid_argument(
                "protobuf field number zero is invalid",
            ));
        }
        budget.descriptor_lookups_left = budget
            .descriptor_lookups_left
            .checked_sub(message.field.len())
            .ok_or_else(|| {
                resource_exhausted("protobuf descriptor work exceeds the wire budget")
            })?;
        let known = message
            .field
            .iter()
            .enumerate()
            .find(|(_, field)| field.number == Some(field_number as i32));
        let Some((field_index, field)) = known else {
            skip_unknown_field(wire_type, &mut bytes)?;
            continue;
        };
        field_counts[field_index] += 1;
        let repeated = field.label == Some(Label::Repeated as i32);
        if !repeated && field_counts[field_index] > 1 {
            return Err(Status::invalid_argument(
                "duplicate singular protobuf field is not canonical",
            ));
        }
        if let Some(oneof_index) = field.oneof_index {
            let oneof_index = usize::try_from(oneof_index)
                .map_err(|_| Status::internal("protobuf oneof descriptor is invalid"))?;
            let count = oneof_counts
                .get_mut(oneof_index)
                .ok_or_else(|| Status::internal("protobuf oneof descriptor is invalid"))?;
            *count += 1;
            if *count > 1 {
                return Err(Status::invalid_argument(
                    "duplicate protobuf oneof selection is not canonical",
                ));
            }
        }
        let nested_descriptor = if field.r#type == Some(Type::Message as i32) {
            if nested_descriptors[field_index].is_none() {
                budget.descriptor_lookups_left = budget
                    .descriptor_lookups_left
                    .checked_sub(MAX_DESCRIPTOR_MESSAGE_TYPES)
                    .ok_or_else(|| {
                        resource_exhausted("protobuf descriptor work exceeds the wire budget")
                    })?;
                let type_name = field
                    .type_name
                    .as_deref()
                    .ok_or_else(|| Status::internal("protobuf message field has no type name"))?;
                nested_descriptors[field_index] = Some(
                    find_message_by_type_name(descriptors, type_name).ok_or_else(|| {
                        Status::internal("protobuf nested message descriptor is absent")
                    })?,
                );
            }
            nested_descriptors[field_index]
        } else {
            None
        };
        let item_count = scan_field(
            descriptors,
            message,
            field,
            nested_descriptor,
            wire_type,
            &mut bytes,
            depth,
            budget,
        )?;
        if repeated {
            let limit = repeated_field_limit(
                message.name.as_deref().unwrap_or_default(),
                field.number.unwrap_or_default(),
            )
            .ok_or_else(|| {
                Status::failed_precondition("repeated protobuf field has no wire budget")
            })?;
            field_counts[field_index] = field_counts[field_index]
                .checked_add(item_count.saturating_sub(1))
                .ok_or_else(|| resource_exhausted("protobuf repeated field count overflowed"))?;
            if field_counts[field_index] > limit {
                return Err(resource_exhausted(
                    "protobuf repeated field exceeds the wire item budget",
                ));
            }
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire descriptor, limits, and recursion state stay explicit"
)]
fn scan_field(
    descriptors: &FileDescriptorSet,
    message: &DescriptorProto,
    field: &FieldDescriptorProto,
    nested_descriptor: Option<&DescriptorProto>,
    wire_type: u8,
    bytes: &mut &[u8],
    depth: usize,
    budget: &mut WireBudget,
) -> Result<usize, Status> {
    let field_type = Type::try_from(field.r#type.unwrap_or_default())
        .map_err(|_| Status::internal("protobuf field descriptor type is invalid"))?;
    let repeated = field.label == Some(Label::Repeated as i32);
    match (field_type, wire_type) {
        (Type::Double | Type::Fixed64 | Type::Sfixed64, 1) => {
            take_exact(bytes, 8)?;
            Ok(1)
        }
        (
            Type::Int64
            | Type::Uint64
            | Type::Int32
            | Type::Bool
            | Type::Uint32
            | Type::Enum
            | Type::Sint32
            | Type::Sint64,
            0,
        ) => {
            read_varint(bytes)?;
            Ok(1)
        }
        (Type::Float | Type::Fixed32 | Type::Sfixed32, 5) => {
            take_exact(bytes, 4)?;
            Ok(1)
        }
        (Type::String | Type::Bytes, 2) => {
            let value = take_length_delimited(bytes)?;
            let limit = scalar_field_byte_limit(
                message.name.as_deref().unwrap_or_default(),
                field.number.unwrap_or_default(),
            );
            if value.len() > limit {
                return Err(resource_exhausted(
                    "protobuf scalar field exceeds the wire byte budget",
                ));
            }
            Ok(1)
        }
        (Type::Message, 2) => {
            let nested = take_length_delimited(bytes)?;
            let descriptor = nested_descriptor
                .ok_or_else(|| Status::internal("protobuf nested message descriptor is absent"))?;
            scan_message(descriptors, descriptor, nested, depth + 1, budget)?;
            Ok(1)
        }
        (
            Type::Double
            | Type::Float
            | Type::Int64
            | Type::Uint64
            | Type::Int32
            | Type::Fixed64
            | Type::Fixed32
            | Type::Bool
            | Type::Uint32
            | Type::Enum
            | Type::Sfixed32
            | Type::Sfixed64
            | Type::Sint32
            | Type::Sint64,
            2,
        ) if repeated => count_packed_items(field_type, take_length_delimited(bytes)?),
        (Type::Group, _) => Err(Status::invalid_argument(
            "protobuf groups are unsupported by the v1 wire contract",
        )),
        _ => Err(Status::invalid_argument(
            "protobuf field uses a non-canonical wire type",
        )),
    }
}

fn count_packed_items(field_type: Type, mut bytes: &[u8]) -> Result<usize, Status> {
    match field_type {
        Type::Double | Type::Fixed64 | Type::Sfixed64 => {
            if !bytes.len().is_multiple_of(8) {
                return Err(Status::invalid_argument(
                    "packed fixed64 field has invalid length",
                ));
            }
            Ok(bytes.len() / 8)
        }
        Type::Float | Type::Fixed32 | Type::Sfixed32 => {
            if !bytes.len().is_multiple_of(4) {
                return Err(Status::invalid_argument(
                    "packed fixed32 field has invalid length",
                ));
            }
            Ok(bytes.len() / 4)
        }
        _ => {
            let mut count = 0_usize;
            while !bytes.is_empty() {
                read_varint(&mut bytes)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| resource_exhausted("packed field item count overflowed"))?;
                if count > DEFAULT_REPEATED_ITEMS {
                    return Err(resource_exhausted(
                        "packed protobuf field exceeds the wire item budget",
                    ));
                }
            }
            Ok(count)
        }
    }
}

fn skip_unknown_field(wire_type: u8, bytes: &mut &[u8]) -> Result<(), Status> {
    match wire_type {
        0 => {
            read_varint(bytes)?;
        }
        1 => {
            take_exact(bytes, 8)?;
        }
        2 => {
            take_length_delimited(bytes)?;
        }
        5 => {
            take_exact(bytes, 4)?;
        }
        _ => return Err(Status::invalid_argument("protobuf wire type is invalid")),
    }
    Ok(())
}

fn read_varint(bytes: &mut &[u8]) -> Result<u64, Status> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let Some((&byte, rest)) = bytes.split_first() else {
            return Err(Status::invalid_argument("protobuf varint is truncated"));
        };
        *bytes = rest;
        if shift == 63 && byte > 1 {
            return Err(Status::invalid_argument("protobuf varint overflows u64"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Status::invalid_argument("protobuf varint is too long"))
}

fn take_length_delimited<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], Status> {
    let length = usize::try_from(read_varint(bytes)?)
        .map_err(|_| resource_exhausted("protobuf length exceeds this platform"))?;
    take_exact(bytes, length)
}

fn take_exact<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], Status> {
    if bytes.len() < length {
        return Err(Status::invalid_argument("protobuf field is truncated"));
    }
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(value)
}

fn resource_exhausted(message: &'static str) -> Status {
    Status::resource_exhausted(message)
}

fn repeated_field_limit(message: &str, number: i32) -> Option<usize> {
    let limit = match (message, number) {
        ("ErrorStatus", 4) | ("IngestAck", 7) => 1_024,
        ("CapabilityManifestV1", 4) => 256,
        ("RequestContext", 11) => 256,
        ("RequestContext", 4 | 5)
        | ("AudiencePurposeGrant", 2)
        | ("AccessPolicy", 2..=6)
        | ("ObserveRequest", 4)
        | ("SourceRevisionManifest", 7)
        | ("StreamObservation", 3)
        | ("SubscribeRequest", 2)
        | ("MemoryEvent", 5 | 6)
        | ("MemoryLinks", 6..=8)
        | ("MemoryDocument", 9 | 10)
        | ("TimelineResponse", 1)
        | ("TraverseRequest", 2 | 4)
        | ("TraverseResponse", 1)
        | ("RecallTrace", 5)
        | ("RecallResponse", 1)
        | ("ContextPackTrace", 14)
        | ("CanonicalContextPackV1", 8 | 9)
        | ("CanonicalContextPackSectionV1", 2)
        | ("HighLevelWriteRequest", 8) => DEFAULT_REPEATED_ITEMS,
        ("CanonicalContextPackV1", 7) => MAX_CANONICAL_CONTEXT_PACK_SECTIONS,
        _ => return None,
    };
    Some(limit)
}

fn scalar_field_byte_limit(message: &str, number: i32) -> usize {
    match (message, number) {
        ("GatewayFrameAttestation", 1) => MAX_GATEWAY_ID_BYTES,
        ("GatewayFrameAttestation", 2) => MAX_GATEWAY_ATTESTATION_BYTES,
        _ => MAX_MESSAGE_BYTES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{GatewayFrameAttestation, ObserveRequest, ObserveResponse, RecallRequest};
    use prost::bytes::{BufMut, BytesMut};
    use prost_types::field_descriptor_proto::Label;

    #[test]
    fn every_repeated_schema_field_has_an_explicit_budget() {
        let descriptors = descriptor_set().expect("descriptor set");
        for file in &descriptors.file {
            for message in &file.message_type {
                assert_repeated_fields_budgeted(message);
            }
        }
    }

    #[test]
    fn every_message_descriptor_fits_the_static_allocation_free_budget() {
        let descriptors = descriptor_set().expect("descriptor set");
        let message_type_count: usize = descriptors
            .file
            .iter()
            .flat_map(|file| &file.message_type)
            .map(count_message_types)
            .sum();
        assert!(
            message_type_count <= MAX_DESCRIPTOR_MESSAGE_TYPES,
            "descriptor type lookup exceeds its conservative work charge"
        );
        for file in &descriptors.file {
            for message in &file.message_type {
                assert_static_descriptor_budget(message);
            }
        }
    }

    fn count_message_types(message: &DescriptorProto) -> usize {
        1 + message
            .nested_type
            .iter()
            .map(count_message_types)
            .sum::<usize>()
    }

    fn assert_static_descriptor_budget(message: &DescriptorProto) {
        assert!(
            message.field.len() <= MAX_DESCRIPTOR_FIELDS_PER_MESSAGE,
            "{} exceeds the static field budget",
            message.name.as_deref().unwrap_or_default()
        );
        assert!(
            message.oneof_decl.len() <= MAX_DESCRIPTOR_ONEOFS_PER_MESSAGE,
            "{} exceeds the static oneof budget",
            message.name.as_deref().unwrap_or_default()
        );
        for nested in &message.nested_type {
            assert_static_descriptor_budget(nested);
        }
    }

    fn assert_repeated_fields_budgeted(message: &DescriptorProto) {
        for field in &message.field {
            if field.label == Some(Label::Repeated as i32) {
                assert!(
                    repeated_field_limit(
                        message.name.as_deref().expect("message name"),
                        field.number.expect("field number")
                    )
                    .is_some(),
                    "{}.{} has no explicit wire budget",
                    message.name.as_deref().unwrap_or_default(),
                    field.name.as_deref().unwrap_or_default()
                );
            }
        }
        for nested in &message.nested_type {
            assert_repeated_fields_budgeted(nested);
        }
    }

    #[test]
    fn every_service_input_resolves_to_a_named_budgeted_message() {
        let descriptors = descriptor_set().expect("descriptor set");
        for file in &descriptors.file {
            for service in &file.service {
                for method in &service.method {
                    let input = method.input_type.as_deref().expect("method input type");
                    assert!(
                        find_message_by_type_name(descriptors, input).is_some(),
                        "service input {input} has no descriptor-backed wire budget"
                    );
                }
            }
        }
    }

    #[test]
    fn every_generated_client_and_server_method_uses_the_bounded_codec() {
        let descriptors = descriptor_set().expect("descriptor set");
        let method_count: usize = descriptors
            .file
            .iter()
            .flat_map(|file| &file.service)
            .map(|service| service.method.len())
            .sum();
        let generated = include_str!(concat!(env!("OUT_DIR"), "/contextdb.v1.rs"));
        assert!(!generated.contains("tonic_prost::ProstCodec"));
        assert_eq!(
            generated
                .matches("crate::BoundedProstCodec::default()")
                .count(),
            method_count * 2,
            "every RPC must use the bounded codec on both generated client and server paths"
        );
    }

    #[test]
    fn allocation_amplifying_repeated_entries_fail_before_prost_decode() {
        let mut raw = BytesMut::new();
        for _ in 0..=DEFAULT_REPEATED_ITEMS {
            raw.put_u8((4 << 3) | 2);
            raw.put_u8(0);
        }
        let error = admit_wire_message("contextdb.v1", ObserveRequest::NAME, &raw)
            .expect_err("excess metadata cardinality must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn nested_authentication_sets_and_duplicate_context_fail_closed() {
        let mut nested = BytesMut::new();
        for _ in 0..=DEFAULT_REPEATED_ITEMS {
            nested.put_u8((4 << 3) | 2);
            nested.put_u8(0);
        }
        let mut raw = BytesMut::new();
        raw.put_u8((1 << 3) | 2);
        raw.put_u8(u8::try_from(nested.len()).unwrap_or(0));
        if nested.len() >= 128 {
            raw.clear();
            raw.put_u8((1 << 3) | 2);
            put_varint(&mut raw, nested.len() as u64);
        }
        raw.extend_from_slice(&nested);
        let error = admit_wire_message("contextdb.v1", RecallRequest::NAME, &raw)
            .expect_err("nested audience amplification must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);

        let duplicate = [0x0a, 0x00, 0x0a, 0x00];
        let error = admit_wire_message("contextdb.v1", RecallRequest::NAME, &duplicate)
            .expect_err("duplicate singular context must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn streaming_attestation_envelope_is_bounded_before_prost_decode() {
        let mut raw = BytesMut::new();
        raw.put_u8((2 << 3) | 2);
        put_varint(&mut raw, (MAX_GATEWAY_ATTESTATION_BYTES + 1) as u64);
        raw.extend_from_slice(&vec![b'a'; MAX_GATEWAY_ATTESTATION_BYTES + 1]);
        let error = admit_wire_message("contextdb.v1", GatewayFrameAttestation::NAME, &raw)
            .expect_err("oversized attestation token must fail");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn legitimate_message_uses_bounded_codec() {
        let message = RecallRequest::default();
        let raw = message.encode_to_vec();
        admit_wire_message("contextdb.v1", RecallRequest::NAME, &raw).expect("wire admission");
        assert_eq!(
            RecallRequest::decode(raw.as_slice()).expect("decode"),
            message
        );

        let _: BoundedProstCodec<ObserveResponse, ObserveRequest> = Default::default();
    }

    fn put_varint(buffer: &mut BytesMut, mut value: u64) {
        while value >= 0x80 {
            buffer.put_u8((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        buffer.put_u8(value as u8);
    }
}
