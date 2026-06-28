<#
.SYNOPSIS
  Generate a machine-readable CI gate report (gate-report.json).
  Runs all G1/G3 gate commands, captures outputs and exit codes,
  and produces a JSON artifact per PLAN.md §4.3.
#>

param(
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path (Join-Path $root $OutputDir) "gate-report.json"

# Ensure output directory exists
$outDir = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# ── Helper: run a command, capture output and exit code ──────────────────
function Run-Step {
    param([string]$Label, [scriptblock]$ScriptBlock)
    Write-Host "--- [$Label] ---" -ForegroundColor Cyan
    $lines = [System.Collections.Generic.List[string]]::new()
    & $ScriptBlock *>&1 | ForEach-Object { $lines.Add("$_") }
    $ec = $LASTEXITCODE
    $text = $lines -join "`n"
    if ($text) { Write-Host $text }
    if ($ec -eq 0) {
        Write-Host "[OK] $Label" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $Label (exit code $ec)" -ForegroundColor Red
    }
    return @{
        command = $Label
        exit_code = $ec
        output = $text
    }
}

# ── Steps ────────────────────────────────────────────────────────────────
$steps = @()

$steps += Run-Step "cargo fmt --all -- --check" {
    Set-Location $root; cargo fmt --all -- --check 2>&1
}

$steps += Run-Step "cargo clippy --workspace --all-targets --all-features -- -D warnings" {
    Set-Location $root; cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1
}

$steps += Run-Step "cargo check --workspace --all-targets --all-features" {
    Set-Location $root; cargo check --workspace --all-targets --all-features 2>&1
}

$steps += Run-Step "cargo test --workspace --all-features" {
    Set-Location $root; cargo test --workspace --all-features 2>&1
}

$steps += Run-Step "cargo test --doc --workspace --all-features" {
    Set-Location $root; cargo test --doc --workspace --all-features 2>&1
}

$steps += Run-Step "scripts/check-deps.ps1" {
    & (Join-Path $root "scripts/check-deps.ps1") 2>&1
}

$steps += Run-Step "scripts/check-specs.ps1" {
    & (Join-Path $root "scripts/check-specs.ps1") 2>&1
}

$steps += Run-Step "scripts/check-fixtures.ps1" {
    & (Join-Path $root "scripts/check-fixtures.ps1") 2>&1
}

$steps += Run-Step "scripts/check-plan-ledger.ps1" {
    & (Join-Path $root "scripts/check-plan-ledger.ps1") 2>&1
}

# G3 — freeze check (fail if missing — hard gate scripts are mandatory)
$freezeCheckScript = Join-Path $root "scripts/check-format-freeze.ps1"
if (-not (Test-Path -LiteralPath $freezeCheckScript)) {
    Write-Host "[FAIL] G3 freeze check script missing: $freezeCheckScript" -ForegroundColor Red
    exit 1
}
$steps += Run-Step "scripts/check-format-freeze.ps1" {
    & $freezeCheckScript 2>&1
}

# G3 — fuzz smoke (fail if missing — hard gate scripts are mandatory)
$fuzzSmokeScript = Join-Path $root "scripts/fuzz-smoke.ps1"
if (-not (Test-Path -LiteralPath $fuzzSmokeScript)) {
    Write-Host "[FAIL] G3 fuzz smoke script missing: $fuzzSmokeScript" -ForegroundColor Red
    exit 1
}
$steps += Run-Step "scripts/fuzz-smoke.ps1" {
    & $fuzzSmokeScript 2>&1
}

# ── Parse test counts (capture all crate-level results) ─────────────────
$totalPassed = 0; $totalFailed = 0; $totalIgnored = 0
$re = [System.Text.RegularExpressions.Regex]::new('(?<passed>\d+) passed;\s*(?<failed>\d+) failed;\s*(?<ignored>\d+) ignored')
foreach ($step in $steps) {
    if ($step.command -eq "cargo test --workspace --all-features") {
        $text = if ($null -eq $step.output) { "" } else { "$($step.output)" }
        foreach ($m in $re.Matches($text)) {
            $totalPassed += [int]$m.Groups['passed'].Value
            $totalFailed += [int]$m.Groups['failed'].Value
            $totalIgnored += [int]$m.Groups['ignored'].Value
        }
    }
}

$testCounts = @{
    passed = $totalPassed
    failed = $totalFailed
    ignored = $totalIgnored
}

# ── Ignored test list ────────────────────────────────────────────────────
$ignoredTests = @()
$ignoreMatches = Select-String -Path (Join-Path $root "crates/**/*.rs") -Pattern '#\[ignore\]' -CaseSensitive 2>$null
if ($ignoreMatches) {
    $ignoredTests = $ignoreMatches | ForEach-Object {
        $file = $_.Filename
        $line = $_.LineNumber
        "$file`:$line"
    }
}

# ── Fixture manifest checksum ────────────────────────────────────────────
$manifestPath = Join-Path $root "tests/vectors/format-v1/manifest.json"
$fixtureChecksum = $null
if (Test-Path -LiteralPath $manifestPath) {
    $hash = Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256
    $fixtureChecksum = @{
        manifest = "tests/vectors/format-v1/manifest.json"
        sha256 = $hash.Hash.ToLowerInvariant()
    }
}

# ── Metadata ─────────────────────────────────────────────────────────────
$commitSha = "unknown"
try {
    $commitSha = (git rev-parse HEAD 2>$null).Trim()
} catch {}
if (-not $commitSha -or $commitSha -eq "unknown") {
    $commitSha = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "unknown" }
}

$rustcVersion = "unknown"
try {
    $rustcVersion = (rustc --version 2>$null).Trim()
} catch {}

$osInfo = [Environment]::OSVersion.Platform.ToString()
$arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
try {
    $uname = uname -m 2>$null
    if ($uname) { $arch = $uname.Trim() }
} catch {}

# ── Assemble report ──────────────────────────────────────────────────────
$report = @{
    commit = $commitSha
    rustc_version = $rustcVersion
    os = $osInfo
    architecture = $arch
    timestamp = (Get-Date -Format "o")
    steps = $steps
    test_counts = $testCounts
    fixture_checksum = $fixtureChecksum
    ignored_test_list = $ignoredTests
}

# ── Write JSON ──────────────────────────────────────────────────────────
$json = $report | ConvertTo-Json -Depth 10
Set-Content -LiteralPath $outputPath -Value $json -Encoding UTF8
Write-Host "gate-report.json written to $outputPath" -ForegroundColor Green

# ── Determine overall exit code ──────────────────────────────────────────
$anyFailed = $steps | Where-Object { $_.exit_code -ne 0 } | Select-Object -First 1
$testCountsOk = ($totalPassed -ne 0 -or $totalFailed -ne 0)
$noIgnoredTests = ($totalIgnored -eq 0)
$fixtureChecksumOk = ($null -ne $fixtureChecksum)

if (-not $testCountsOk) {
    Write-Host "[FAIL] No test counts parsed. The output may have an unexpected format." -ForegroundColor Red
}
if (-not $noIgnoredTests) {
    Write-Host "[FAIL] Ignored tests detected ($totalIgnored from cargo test output). G1 gate forbids #[ignore]." -ForegroundColor Red
}
if (-not $fixtureChecksumOk) {
    Write-Host "[FAIL] Fixture manifest checksum missing. G1 gate requires non-null checksum." -ForegroundColor Red
}
if ($anyFailed) {
    Write-Host "Gate FAILED. Some steps had non-zero exit codes." -ForegroundColor Red
}
if ($testCountsOk -and $noIgnoredTests -and $fixtureChecksumOk -and -not $anyFailed) {
    Write-Host "All gate steps passed." -ForegroundColor Green
    exit 0
}
exit 1
