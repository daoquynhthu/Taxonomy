# EternalCore — v4 (Rust)

A content-addressed, cryptographically verifiable, distributed generic object persistence engine.

Part of the **Seed Plan**: a protocol for preserving a complete snapshot of human knowledge.

## Repository Structure

```
├── Cargo.toml              # Rust workspace root
├── crates/
│   ├── eternal-format/     # Canonical encoding, domain-separated hashing, record types
│   ├── eternal-store/      # Active segment, sealed packs, crash recovery
│   ├── eternal-core/       # Repository logic, SMT, commits, merge, GC
│   ├── eternal-crypto/     # Ed25519 signing, XChaCha20-Poly1305 encryption
│   ├── eternal-net/        # Sync protocol, remote adapters
│   └── eternal-cli/        # CLI binary
├── docs/
│   └── ARCHITECTURE.md     # v4 architecture specification (authoritative)
├── prototype/              # v3 Python prototype (archived)
├── tests/                  # Integration tests
├── fuzz/                   # Fuzz targets
└── benches/                # Criterion benchmarks
```

## Status

**Phase F3 — Record schemas and format fixtures.** All 8 repository authority payload schemas implemented (RepositoryGenesisPayload, PublicKeyEntry, RefPermissionEntry, PolicyRecordPayload, PasswordKdfDescriptor, KeySlot, WrappedDek, KeyringRecordPayload) with field validation, sorted-unique enforcement, deterministic CBOR round-trip encoding, and 341 unit tests passing.

The authoritative architecture document is [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
