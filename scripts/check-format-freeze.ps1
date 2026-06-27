<#
.SYNOPSIS
  Check format-v1 freeze baseline.
  Verifies that all format-defining source files, fixtures, and fuzz targets
  still match their committed SHA-256 hashes from freeze-baseline.json.
  If any hash differs, v1 bytes have changed — G3 must be reopened.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$baselinePath = Join-Path $root "tests/vectors/format-v1/freeze-baseline.json"
$exitCode = 0

if (-not (Test-Path -LiteralPath $baselinePath)) {
    Write-Host "[FAIL] freeze-baseline.json not found at $baselinePath" -ForegroundColor Red
    Write-Host "  Run scripts/gen-format-freeze-baseline.ps1 to create it." -ForegroundColor Yellow
    exit 1
}

$baseline = Get-Content -Raw -LiteralPath $baselinePath | ConvertFrom-Json

Write-Host "=== Format v1 freeze baseline check ===" -ForegroundColor Cyan
Write-Host "Frozen at commit: $($baseline.frozen_commit)"
Write-Host ""

function Check-Hash {
    param([string]$Label, [string]$Path, [string]$Expected)
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "[FAIL] $Label — file not found: $Path" -ForegroundColor Red
        return $false
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) {
        Write-Host "[FAIL] $Label" -ForegroundColor Red
        Write-Host "  expected: $expected"
        Write-Host "  actual:   $actual"
        Write-Host "  file: $Path"
        return $false
    }
    Write-Host "[OK] $Label" -ForegroundColor Green
    return $true
}

# ── Source files ─────────────────────────────────────────────────────────
Write-Host "--- Source files ---" -ForegroundColor Cyan
foreach ($entry in $baseline.source_files.PSObject.Properties) {
    $path = Join-Path $root $entry.Name
    if (-not (Check-Hash $entry.Name $path $entry.Value)) { $exitCode = 1 }
}

# ── Fuzz targets ─────────────────────────────────────────────────────────
Write-Host "--- Fuzz targets ---" -ForegroundColor Cyan
foreach ($entry in $baseline.fuzz_targets.PSObject.Properties) {
    $path = Join-Path $root $entry.Name
    if (-not (Check-Hash $entry.Name $path $entry.Value)) { $exitCode = 1 }
}

# ── Fixtures ─────────────────────────────────────────────────────────────
Write-Host "--- Fixtures ---" -ForegroundColor Cyan
$fixturesDir = Join-Path $root "tests/vectors/format-v1"
foreach ($entry in $baseline.fixtures.PSObject.Properties) {
    $path = Join-Path $fixturesDir $entry.Name
    if (-not (Check-Hash $entry.Name $path $entry.Value)) { $exitCode = 1 }
}

# ── Result ───────────────────────────────────────────────────────────────
Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "Freeze baseline intact. No v1 bytes changed." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Freeze baseline mismatch. G3 must be reopened." -ForegroundColor Red
}
exit $exitCode
