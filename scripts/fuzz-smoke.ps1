<#
.SYNOPSIS
  Run a bounded smoke fuzz job for every fuzz target.
  Designed for CI invocation after the standard gate passes.
.DESCRIPTION
  Required environment:
    - nightliy toolchain installed (rustup toolchain list)
    - cargo-fuzz installed (cargo install cargo-fuzz)
    - LLVM lib dir in LIB and PATH (for ASan DLL on Windows)
  Every fuzz argument is hard-coded to enforce resource limits:
    -max_len=65536       Input size cap (unbounded allocation prevention)
    -timeout=2           Per-input time cap (infinite-loop prevention)
    -rss_limit_mb=512    Memory cap (OOM prevention)
    -runs=50000          Bounded iteration count

  Output: fuzz-smoke-report.json containing per-target results.
#>

param(
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$fuzzDir = Join-Path $root "fuzz"
if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $outputPath = Join-Path $OutputDir "fuzz-smoke-report.json"
} else {
    $outputPath = Join-Path $root (Join-Path $OutputDir "fuzz-smoke-report.json")
}

# Ensure output directory
$outDir = Split-Path -Parent $outputPath
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# ── Detect nightly ───────────────────────────────────────────────────────
$nightlyAvailable = $false
$output = rustup toolchain list 2>&1
if ("$output" -match "nightly") {
    $nightlyAvailable = $true
}
if (-not $nightlyAvailable) {
    Write-Host "[SKIP] nightly toolchain not installed — cannot build fuzz targets" -ForegroundColor Yellow
    $report = @{
        skipped = $true
        reason = "nightly toolchain not installed"
        timestamp = (Get-Date -Format "o")
    }
    $json = $report | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $outputPath -Value $json -Encoding UTF8
    exit 0   # skip is not a failure
}

# ── Ensure cargo-fuzz ─────────────────────────────────────────────────────
$cargoFuzzCheck = Get-Command "cargo-fuzz" -ErrorAction SilentlyContinue
if (-not $cargoFuzzCheck) {
    Write-Host "[SKIP] cargo-fuzz not installed — run 'cargo install cargo-fuzz'" -ForegroundColor Yellow
    $report = @{
        skipped = $true
        reason = "cargo-fuzz not installed"
        timestamp = (Get-Date -Format "o")
    }
    $json = $report | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $outputPath -Value $json -Encoding UTF8
    exit 0
}

# ── LLVM/ASan setup (Windows) ────────────────────────────────────────────
$llvmLib = "C:\Program Files\LLVM\lib\clang\22\lib\windows"
if (Test-Path -LiteralPath $llvmLib) {
    $env:LIB = "$llvmLib;$env:LIB"
    $env:PATH = "$llvmLib;$env:PATH"
}

# ── Common fuzz arguments ────────────────────────────────────────────────
$fuzzArgs = @(
    "-max_len=65536"
    "-timeout=2"
    "-rss_limit_mb=512"
    "-runs=50000"
)

# ── Helper: run one fuzz target ──────────────────────────────────────────
function Run-FuzzTarget {
    param([string]$TargetName)
    Write-Host "--- Fuzz target: $TargetName ---" -ForegroundColor Cyan
    $lines = [System.Collections.Generic.List[string]]::new()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ec = 0
    Push-Location $fuzzDir
    $output = & "cargo" "+nightly" "fuzz" "run" $TargetName "--" @fuzzArgs 2>&1
    $ec = $LASTEXITCODE
    Pop-Location
    foreach ($line in $output) {
        $lines.Add("$line")
    }
    $sw.Stop()
    $text = $lines -join "`n"
    Write-Host $text

    # Parse summary line: "#N	DONE	cov: M	ft: K	corp: C/Sb	lim: L	exec/s: E	rss: RMb"
    $doneMatch = [regex]::Match($text, '#50000\s+DONE\s+cov:\s+(\d+)\s+ft:\s+(\d+)\s+corp:\s+(\d+)[/ ](\d+)b.*?rss:\s+(\d+)Mb')
    $runs = if ($doneMatch.Success) { 50000 } else { $null }
    $coverage = if ($doneMatch.Success) { [int]$doneMatch.Groups[1].Value } else { $null }
    $corpus = if ($doneMatch.Success) { [int]$doneMatch.Groups[3].Value } else { $null }
    $peakRss = if ($doneMatch.Success) { [int]$doneMatch.Groups[5].Value } else { $null }

    $hasCrashes = $text -cmatch "\bCRASH\b"
    $hasTimeouts = $text -cmatch "\bTIMEOUT\b"
    $hasPanic = $text -match "panicked at"

    $result = @{
        target = $TargetName
        exit_code = $ec
        elapsed_seconds = [int]$sw.Elapsed.TotalSeconds
        runs = $runs
        coverage = $coverage
        corpus_entries = $corpus
        peak_rss_mb = $peakRss
        crashed = $hasCrashes
        timed_out = $hasTimeouts
        panicked = $hasPanic
        output = $text
    }

    if ($ec -eq 0 -and -not $hasCrashes -and -not $hasTimeouts -and -not $hasPanic) {
        Write-Host ("[OK] {0}: {1} runs, {2}Mb RSS, no crashes" -f $TargetName, $runs, $peakRss) -ForegroundColor Green
    } else {
        Write-Host ("[FAIL] {0} (exit={1} crash={2} timeout={3} panic={4})" -f $TargetName, $ec, $hasCrashes, $hasTimeouts, $hasPanic) -ForegroundColor Red
    }

    return $result
}

# ── Run all targets ──────────────────────────────────────────────────────
$commitSha = "unknown"
$null = git -C $root rev-parse HEAD 2>$null
if ($LASTEXITCODE -eq 0) {
    $commitSha = (git -C $root rev-parse HEAD).Trim()
}

$results = @()
$results += Run-FuzzTarget "cbor"
$results += Run-FuzzTarget "names"

# ── Assemble report ──────────────────────────────────────────────────────
$overallPass = ($results | Where-Object { $_.exit_code -ne 0 -or $_.crashed -or $_.timed_out -or $_.panicked }).Count -eq 0

$report = @{
    commit = $commitSha
    timestamp = (Get-Date -Format "o")
    targets = $results
    passed = $overallPass
}

$json = $report | ConvertTo-Json -Depth 10
Set-Content -LiteralPath $outputPath -Value $json -Encoding UTF8
Write-Host "fuzz-smoke-report.json written to $outputPath" -ForegroundColor Green

if ($overallPass) {
    Write-Host "All fuzz smoke tests passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some fuzz smoke tests FAILED." -ForegroundColor Red
    exit 1
}
