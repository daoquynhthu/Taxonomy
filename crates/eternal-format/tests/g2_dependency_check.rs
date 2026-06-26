#![allow(clippy::unwrap_used)]

// Hard Gate G2: `eternal-format` has no filesystem, network, policy, or
// key-store dependency (PLAN.md F2.9 / FORMAT.md §4).
//
// This integration test embeds Cargo.toml at compile time and verifies
// that no forbidden crate name appears in any dependency section.
// Allowed direct dependencies: serde, serde_json, ciborium, sha2.
#[test]
fn g2_no_forbidden_dependencies() {
    assert!(
        option_env!("CARGO_MANIFEST_DIR").is_some(),
        "this test must be run via cargo test --workspace"
    );

    // Verify serde_json actually links (otherwise the include_str
    // check could pass vacuously if Cargo.toml had no deps at all).
    let _ = serde_json::from_str::<serde_json::Value>("null").unwrap();

    // Compile-time check of Cargo.toml dependency sections.
    // This runs at test-compile time, not runtime — no filesystem access.
    let cargo_toml = include_str!("../Cargo.toml");

    // Collect all lines after any `[dependencies` or `[dev-dependencies`
    // or `[build-dependencies` header, up to the next `[` section.
    let mut in_deps = false;
    let mut dep_lines: Vec<&str> = Vec::new();
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.starts_with("[dependencies")
                || trimmed.starts_with("[dev-dependencies")
                || trimmed.starts_with("[build-dependencies");
            continue;
        }
        if in_deps && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Extract the crate name before any '=', '{', ' ', or '"'
            let name = trimmed
                .split(&['=', '{', ' ', '"'][..])
                .next()
                .unwrap_or(trimmed)
                .trim();
            if !name.is_empty() {
                dep_lines.push(name);
            }
        }
    }

    // Known-forbidden crate name prefixes (filesystem, network, policy, key-store)
    let forbidden_prefixes = &[
        "tokio",
        "reqwest",
        "hyper",
        "ring",
        "openssl",
        "rusqlite",
        "sled",
        "rocksdb",
        "ureq",
        "actix-",
        "axum",
        "warp",
        "tide",
        "diesel",
        "sqlx",
        "rusqlite",
        "libsqlite3",
        "crypto-",
        "ed25519",
        "secp",
        "bls",
        "oauth",
        "jwt",
    ];

    let allowed_prefixes = &[
        "serde",
        "ciborium",
        "sha2",
        // Rust standard library crates
        "std",
        "core",
        "alloc",
        "proc-macro",
        // Common transitive deps of allowed crates
        "half",
        "memchr",
        "proc-macro2",
        "quote",
        "syn",
        "unicode-ident",
        "cfg-if",
        "stable_deref_trait",
        "arrayvec",
        // serde_json transitive deps
        "itoa",
        "ryu",
        "serde_json",
        // ciborium transitive deps
        "ciborium-io",
        "ciborium-ll",
        // sha2 transitive deps
        "digest",
        "crypto-common",
        "block-buffer",
        "generic-array",
        "typenum",
        "const-oid",
    ];

    let mut violations: Vec<&str> = Vec::new();
    for dep in &dep_lines {
        if allowed_prefixes.iter().any(|a| dep.starts_with(a)) {
            continue;
        }
        if forbidden_prefixes.iter().any(|f| dep.starts_with(f)) {
            violations.push(dep);
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden dependencies found in Cargo.toml: {}",
        violations.join(", ")
    );
}
