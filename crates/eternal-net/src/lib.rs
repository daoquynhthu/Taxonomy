#![forbid(unsafe_code)]

//! `eternal-net`: Sync protocol, remote adapters, and transport
//! for EternalCore.
//!
//! Provides the RemoteAdapter trait, local-filesystem adapter,
//! TCP/QUIC transport, and mutual authentication.
//!
//! # Organization
//!
//! - [`protocol`] — Wire protocol framing and negotiation
//! - [`adapter`] — RemoteAdapter trait definition
//! - [`local_fs`] — Local-filesystem remote adapter
//! - [`transport`] — TCP/QUIC transport layer
//! - [`auth`] — Challenge-response Ed25519 authentication

pub mod adapter;
pub mod auth;
pub mod local_fs;
pub mod protocol;
pub mod transport;
