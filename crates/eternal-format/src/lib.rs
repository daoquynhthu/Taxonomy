#![forbid(unsafe_code)]

//! `eternal-format`: Canonical encoding, domain-separated hashing,
//! and record type definitions for EternalCore.
//!
//! This crate is the foundation of the entire v4 protocol:
//! every record, identifier, and hash in the system is defined here.
//!
//! # Organization
//!
//! - [`canonical`] — Deterministic CBOR encoding (RFC 8949)
//! - [`domain`] — Domain-separated SHA-256 hash construction
//! - [`ids`] — Core identifier types (DomainHash, ObjectId, VersionId, etc.)
//! - [`record`] — Record type enums and payload schemas
//! - [`limits`] — Configurable parser size limits

pub mod canonical;
pub mod domain;
pub mod ids;
pub mod limits;
pub mod record;

#[cfg(test)]
mod testing;
