<#
.SYNOPSIS
  Verify required specification documents exist and contain expected headings.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exitCode = 0

$requiredDocs = @(
    "ARCHITECTURE.md", "FORMAT.md", "TRANSACTIONS.md",
    "CRYPTO.md", "POLICY.md", "SYNC.md", "PLAN.md", "Agent.md"
)

$requiredHeadings = @{
    "ARCHITECTURE.md" = @(
        "# EternalCore v4 Architecture",
        "## 1. Purpose and Scope",
        "## 2. System Model and Invariants"
    )
    "FORMAT.md" = @(
        "# EternalCore v4 Storage Format Specification",
        "## 1. Scope"
    )
    "TRANSACTIONS.md" = @(
        "# EternalCore v4 Transactions and Crash-Consistency Specification"
    )
    "CRYPTO.md" = @(
        "# EternalCore v4 Cryptography and Key Management"
    )
    "POLICY.md" = @(
        "# EternalCore v4 Authorization and Policy Specification"
    )
    "SYNC.md" = @(
        "# EternalCore v4 Synchronization Protocol"
    )
    "PLAN.md" = @(
        "# EternalCore v4 Implementation Plan",
        "## 1. Authority and scope"
    )
    "Agent.md" = @(
        "# EternalCore Agent Operating Rules",
        "## 1. Authority"
    )
}

$obsoleteTerms = @("SQLite", "meta.log", "Fernet", "PostgreSQL", "manager_v2")

Write-Host "=== Checking required documents ==="
foreach ($doc in $requiredDocs) {
    $path = Join-Path (Join-Path $root "docs") $doc
    if (Test-Path -LiteralPath $path) {
        Write-Host "  [OK] $doc"
    } else {
        Write-Host "  [FAIL] Missing: docs/$doc" -ForegroundColor Red
        $exitCode = 1
    }
}

Write-Host "=== Checking required headings ==="
foreach ($doc in $requiredHeadings.Keys) {
    $path = Join-Path (Join-Path $root "docs") $doc
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $content = Get-Content -LiteralPath $path -Raw
    foreach ($heading in $requiredHeadings[$doc]) {
        if ($content -match [regex]::Escape($heading)) {
            Write-Host "  [OK] $doc :: $heading"
        } else {
            Write-Host "  [FAIL] $doc missing heading: $heading" -ForegroundColor Red
            $exitCode = 1
        }
    }
}

Write-Host "=== Checking for obsolete terms ==="
$authDocs = $requiredDocs | Where-Object { $_ -ne "Agent.md" }
foreach ($doc in $authDocs) {
    $path = Join-Path (Join-Path $root "docs") $doc
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $content = Get-Content -LiteralPath $path -Raw
    foreach ($term in $obsoleteTerms) {
        $pattern = "(?i)\b$([regex]::Escape($term))\b"
        if ($content -match $pattern) {
            Write-Host "  [FAIL] $doc contains obsolete term: $term" -ForegroundColor Red
            $exitCode = 1
        }
    }
}

Write-Host "=== Checking fixture paths ==="
$fixturePaths = @(
    "tests/vectors/manifest.json",
    "tests/vectors/format-v1.json",
    "tests/vectors/segment-header-v1.bin",
    "tests/vectors/pack-v1.pack",
    "tests/vectors/pack-v1.idx",
    "tests/vectors/store-manifest-v1.cbor"
)
foreach ($fp in $fixturePaths) {
    $full = Join-Path $root $fp
    if (Test-Path -LiteralPath $full) {
        Write-Host "  [OK] $fp"
    } else {
        Write-Host "  [FAIL] Missing fixture: $fp" -ForegroundColor Red
        $exitCode = 1
    }
}

if ($exitCode -eq 0) {
    Write-Host "All specification checks passed." -ForegroundColor Green
} else {
    Write-Host "Some checks FAILED." -ForegroundColor Red
}

exit $exitCode
