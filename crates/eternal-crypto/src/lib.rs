#![forbid(unsafe_code)]

//! `eternal-crypto`: Cryptography for EternalCore.
//!
//! Provides Ed25519 signing/verification, XChaCha20-Poly1305
//! chunk encryption, and key slot management (password-based
//! and recipient-based KEK/DEK wrapping).
//!
//! # Organization
//!
//! - [`signing`] — Ed25519 key generation, signing, verification
//! - [`encryption`] — XChaCha20-Poly1305 AEAD encryption/decryption
//! - [`key_slots`] — Password and X25519 recipient key slots
//! - [`password`] — Argon2id key derivation and calibration

pub mod signing;
pub mod encryption;
pub mod key_slots;
pub mod password;
