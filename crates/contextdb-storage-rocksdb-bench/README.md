# RocksDB benchmark adapter

This package is deliberately excluded from the default ContextDB workspace. It
is an explicit M2 comparison target and brings a C++/FFI toolchain; no ContextDB
runtime or release package depends on it.

Build or run it only when the native benchmark environment is available:

```text
cargo run --release --manifest-path crates/contextdb-storage-rocksdb-bench/Cargo.toml -- 50000
```

The adapter implements the same backend-neutral `StorageEngine` contract. It
uses an atomic RocksDB `WriteBatch`, leaves the WAL enabled, and enables
`WriteOptions::set_sync(true)` for ContextDB `Durability::Sync`.
