# Docker source package

These files describe a non-root, capability-dropped local container with
separate persistent archive and anti-rollback-authority volumes plus
loopback-only host ports in Compose. The image builds the `contextdb` CLI/server
binary and initializes a logical archive on first start.

This is source-level packaging only. The Dockerfile and Compose file were not
built or run in the M18/M19 evidence-plumbing workstream. Therefore they do not
prove image correctness, persistence across restart, health behavior, multi-arch
support, registry publication, image digest, SBOM linkage, or vulnerability
status.

The source Dockerfile pins the reviewed multi-platform Rust and Debian base
indexes by immutable digest. A qualifying release must still record:

- Dockerfile/lockfile/source commit;
- builder and runtime image digests;
- produced OCI manifest-list digest for linux/amd64 and linux/arm64;
- per-platform clean-start, observe, restart, recall, backup/restore, and doctor
  receipts;
- image-bound SBOM and provenance attestation;
- signed artifact manifest and registry publication URI.

Do not place secrets or the state-head authority in the image, Compose file,
repository, or archive volume. The named `contextdb-authority` volume is mounted
at `/var/lib/contextdb-authority`, independently of `contextdb-data`, and the
CLI receives `/var/lib/contextdb-authority/state-head.json` through
`CONTEXTDB_STATE_HEAD_FILE`. The authority directory must remain owned by uid
65532 with no group/other permissions. Backing up or rolling back this volume
together with the archive defeats the local rollback detector; authority
custody and recovery are separate operator responsibilities.

The entrypoint requires exactly one of `CONTEXTDB_TOKEN_KEY_HEX` and
`CONTEXTDB_TOKEN_KEY_FILE`; the Compose template mounts the latter read-only at
`/run/contextdb-secrets/token-key` from the host path named by
`CONTEXTDB_DOCKER_TOKEN_KEY_FILE`. That host file must be outside the repository
and archive directory, contain exactly 64 hexadecimal characters with an
optional single line ending, have no Unix group/other permission bits, and be
owned and readable by container uid 65532, have exactly one hard link, and have
no group/other permission bits. Host/container ownership mapping must be
verified on the target runtime; a read-only bind flag alone does not satisfy the
CLI check.

The network daemon also requires `CONTEXTDB_DOCKER_GATEWAY_ID` and an independent
host file named by `CONTEXTDB_DOCKER_GATEWAY_KEY_FILE`. Compose mounts it at
`/run/contextdb-secrets/gateway-key`; the entrypoint applies the same owner,
link, mode, location and bounded-size checks, then passes the exact hexadecimal
key to the child only through `CONTEXTDB_GATEWAY_KEY_HEX`. The gateway key is not
the database token key. The configured gateway remains responsible for
authenticating the original peer and producing a fresh attestation bound to the
complete authenticated request context.

Key custody/backup/rotation, state-head-custodian rollback protection, and live
volume/secret-mount receipts remain release blockers.
