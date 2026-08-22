# syntax=docker/dockerfile:1.7

FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY bindings/ bindings/
COPY examples/embedded-rust/ examples/embedded-rust/
RUN cargo build --locked --release -p contextdb-cli \
        --no-default-features --features current-server \
    && install -D -m 0755 target/release/contextdb /out/contextdb

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime
ARG CONTEXTDB_UID=65532
ARG CONTEXTDB_GID=65532
RUN groupadd --gid "${CONTEXTDB_GID}" contextdb \
    && useradd --uid "${CONTEXTDB_UID}" --gid "${CONTEXTDB_GID}" \
       --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin contextdb \
    && install -d -o contextdb -g contextdb -m 0700 \
       /var/lib/contextdb /var/lib/contextdb-authority
COPY --from=builder /out/contextdb /usr/local/bin/contextdb
COPY --chown=contextdb:contextdb deploy/docker/entrypoint.sh /usr/local/bin/contextdb-entrypoint
RUN chmod 0755 /usr/local/bin/contextdb-entrypoint
USER contextdb:contextdb
WORKDIR /var/lib/contextdb
VOLUME ["/var/lib/contextdb", "/var/lib/contextdb-authority"]
EXPOSE 7733 7734
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD ["/usr/local/bin/contextdb-entrypoint", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/contextdb-entrypoint"]
