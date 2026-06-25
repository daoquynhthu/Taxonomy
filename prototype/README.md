# EternalCore v3 — Python Prototype (Archived)

This directory contains the original Python prototype of EternalCore.

**Status**: Archived. The v4 Rust rewrite is specified in `docs/ARCHITECTURE.md`.

## Contents

| Path | Description |
|------|-------------|
| `src/manager_v2.py` | Main engine (2272 lines, monolithic) |
| `src/setup.py` | setuptools packaging (package name: `eternal`) |
| `tests/test_e2ee.py` | End-to-end encryption test |
| `tests/test_postgres_adapter.py` | PostgreSQL adapter tests |

## Key v3 Concepts (Not Ported to v4)

- SQLite as authoritative state → replaced by pure file format
- `meta.log` as record of truth → replaced by `ObjectVersion` records
- Loose object files → replaced by active segment + sealed packs
- Fernet encryption → replaced by XChaCha20-Poly1305 with KEK/DEK
- No content chunking → replaced by FastCDC chunking
