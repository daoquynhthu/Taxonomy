#![forbid(unsafe_code)]

//! `eternal-store`: Active segment, sealed packs, store manifest,
//! and crash recovery for EternalCore.
//!
//! This crate implements the physical storage layer:
//! append-only write-ahead logs, content-addressed packfiles,
//! and the CURRENT/StoreManifest atomic switching mechanism.
//!
//! # Organization
//!
//! - [`segment`] — Active segment (WAL) append and read
//! - [`pack`] — Sealed pack read/write
//! - [`pack_index`] — External pack index (fanout + offsets)
//! - [`store_manifest`] — StoreManifest generation management
//! - [`lock`] — Advisory writer lock
//! - [`recovery`] — Crash recovery and segment truncation
//! - [`cache`] — Rebuildable redb-backed location cache

pub mod segment;
pub mod pack;
pub mod pack_index;
pub mod store_manifest;
pub mod lock;
pub mod recovery;
pub mod cache;
