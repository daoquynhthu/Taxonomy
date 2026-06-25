#![forbid(unsafe_code)]

//! `eternal-core`: Repository logic, transactions, SMT, commits,
//! merge, and GC for EternalCore.
//!
//! This crate owns the logical semantics of the system:
//! object versions, sparse Merkle trie, repository commits,
//! branch management, three-way merge, policy enforcement,
//! keyring management, verification, and garbage collection.
//!
//! # Organization
//!
//! - [`repository`] — EternalCore entry point, init/open
//! - [`transaction`] — Atomic multi-object write transactions
//! - [`object`] — ObjectVersion CRUD (put/get/delete/rollback)
//! - [`content`] — ContentManifest + BlobChunk read/write
//! - [`smt`] — 256-level Sparse Merkle Trie
//! - [`commit`] — RepoCommit creation and state transitions
//! - [`refs`] — Ref/CAS/HEAD management
//! - [`merge`] — Three-way merge and conflict reporting
//! - [`policy`] — PolicyRecord chain and authorization
//! - [`keyring`] — KeyringRecord chain and encryption state
//! - [`verify`] — Metadata, storage, and content audit
//! - [`gc`] — Garbage collection and compaction

pub mod commit;
pub mod content;
pub mod gc;
pub mod keyring;
pub mod merge;
pub mod object;
pub mod policy;
pub mod refs;
pub mod repository;
pub mod smt;
pub mod transaction;
pub mod verify;
