# Gateway exact-request attestation v2

The official HTTP and gRPC servers accept only the `v2` exact-request
attestation protocol. There is no context-only or legacy-token fallback.
Application `RequestContext` and `AuthenticatedRequestContext` values are not
transport credentials.

## Token and transcript

The ASCII token is:

```text
v2.<issued_at_ms>.<expires_at_ms>.<nonce_hex_32>.<body_blake3_hex_64>.<mac_hex_64>
```

Decimal values have no leading zeroes. Hex is lowercase. The nonce is 16
cryptographically random bytes and must never be reused during its validity
window. The body digest is unkeyed BLAKE3 over the canonical request body.

The MAC is keyed BLAKE3. Feed each value below as `u64 little-endian byte
length || value`, in order:

1. UTF-8 `contextdb/gateway-exact-request/v2`;
2. service schema version as little-endian `u16` (currently `1`);
3. gateway ID as UTF-8;
4. transport UTF-8 ID, `http` or `grpc`;
5. canonical operation as UTF-8;
6. the raw 32-byte body digest;
7. `issued_at_ms` as little-endian `u64`;
8. `expires_at_ms` as little-endian `u64`;
9. the raw 16-byte nonce.

The server compares both digest and MAC in constant time and atomically consumes
the nonce only after the transcript verifies.

## Canonical request bodies

For HTTP, the operation is `METHOD:/path`, for example
`POST:/v1/recall`, and the body is the exact serialized JSON byte sequence sent
on the wire. The Python, Go, and TypeScript header-provider callbacks receive
that exact path and body so a deployment gateway can create the token after
serialization.

For unary and server-streaming gRPC calls, the operation is the generated full
method name, for example `contextdb.v1.RecallService/Recall`, and the body is the
deterministic canonical Prost semantic encoding (`Message::encode_to_vec`) of
the decoded request. It is deliberately not described as the original protobuf
wire bytes. Before Prost allocates, the server codec performs a bounded
descriptor-driven wire walk, rejects malformed duplicate singular/oneof fields,
and enforces explicit repeated-field, recursion, field-count, byte, and work
budgets. Unknown and noncanonical encodings therefore cannot bypass admission.

Client-streaming `ObservationService/ObserveStream` and
`ObservationService/IngestSnapshot` authenticate every frame. Set the frame's
`gateway_attestation` field to absent, encode and attest those canonical
semantic bytes, then attach `GatewayFrameAttestation { gateway_id, token }`.
Metadata-only stream authentication is rejected.

## Freshness and replay boundary

- Maximum token lifetime is 60 seconds; the default helper lifetime is 30
  seconds; freshness allows at most 5 seconds of clock skew.
- A verifier restart establishes a new acceptance epoch and rejects tokens
  issued before it. Clock rollback therefore fails closed.
- The in-process replay cache holds at most 65,536 unexpired nonces. Saturation
  rejects new requests with `resource_exhausted`; it never evicts an unexpired
  nonce to admit another token.
- Clones inside one process share the same atomic replay cache. Multiple server
  processes require a shared replay authority or sticky routing to one verifier.
  Deploying independent verifier caches behind round-robin routing does not
  provide global one-shot replay protection.
- The server limits HTTP/2 header-list size and per-connection concurrency, but
  an upstream proxy terminates and allocates headers before ContextDB sees them.
  That proxy must enforce equivalent header and connection limits.

The keyed helper in `contextdb-server` is suitable for trusted gateway and
conformance code. SDK clients intentionally expose a per-request provider seam
instead of retaining the deployment's MAC key.
