<#
.SYNOPSIS
  Check format-v1 freeze baseline using git as authority.
  For every file in freeze-baseline.json, verifies its current working-tree
  content matches the state at frozen_commit via git diff.
  If any file differs, v1 bytes have changed — G3 must be reopened.

  The stored SHA-256 hashes in freeze-baseline.json are documentary;
  the authoritative check uses git history, not the JSON hashes.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$baselinePath = Join-Path $root "tests/vectors/format-v1/freeze-baseline.json"
$exitCode = 0

if (-not (Test-Path -LiteralPath $baselinePath)) {
    Write-Host "[FAIL] freeze-baseline.json not found at $baselinePath" -ForegroundColor Red
    Write-Host "  To create baseline: set frozen_commit to current HEAD, then add" -ForegroundColor Yellow
    Write-Host "  SHA-256 hashes for every format-defining source file, fuzz target," -ForegroundColor Yellow
    Write-Host "  and fixture. See existing freeze-baseline.json for structure." -ForegroundColor Yellow
    exit 1
}

$baseline = Get-Content -Raw -LiteralPath $baselinePath | ConvertFrom-Json
$frozenCommit = $baseline.frozen_commit

Write-Host "=== Format v1 freeze baseline check (git-authority mode) ===" -ForegroundColor Cyan
Write-Host "Frozen commit: $frozenCommit"
Write-Host ""

# Verify frozen_commit exists and is an ancestor of HEAD
$null = git rev-parse --verify "$frozenCommit^{commit}" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] frozen_commit '$frozenCommit' is not a valid git commit" -ForegroundColor Red
    exit 1
}

git merge-base --is-ancestor $frozenCommit HEAD 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] frozen_commit '$frozenCommit' is not an ancestor of HEAD" -ForegroundColor Red
    Write-Host "       The baseline commit has been replaced — this is a tamper attempt." -ForegroundColor Red
    Write-Host "       Re-freeze by setting frozen_commit to a valid ancestor of HEAD." -ForegroundColor Yellow
    exit 1
}

# ── Check all sections ────────────────────────────────────────────────────
$allEntries = @()

# Source files
$baseline.source_files.PSObject.Properties | ForEach-Object {
    $allEntries += @{Label = $_.Name; Path = $_.Name; Section = "source"}
}

# Fuzz targets
$baseline.fuzz_targets.PSObject.Properties | ForEach-Object {
    $allEntries += @{Label = $_.Name; Path = $_.Name; Section = "fuzz"}
}

# Fixtures
$fixturesDir = "tests/vectors/format-v1"
$baseline.fixtures.PSObject.Properties | ForEach-Object {
    $allEntries += @{Label = $_.Name; Path = "$fixturesDir/$($_.Name)"; Section = "fixture"}
}

$changedCount = 0
foreach ($entry in $allEntries) {
    $relativePath = $entry.Path
    $fullPath = Join-Path $root $relativePath

    if (-not (Test-Path -LiteralPath $fullPath)) {
        Write-Host "[FAIL] $relativePath — file not found on disk" -ForegroundColor Red
        $exitCode = 1
        $changedCount++
        continue
    }

    # Check if file at frozen_commit differs from working tree
    git diff --quiet $frozenCommit -- $relativePath 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] $relativePath" -ForegroundColor Green
    } else {
        # File does not exist at frozen_commit (new), or content differs
        $null = git show "$frozenCommit`:$relativePath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[NEW] $relativePath — not present at frozen commit $frozenCommit" -ForegroundColor Yellow
        } else {
            Write-Host "[MODIFIED] $relativePath — content differs from frozen commit $frozenCommit" -ForegroundColor Red
        }
        $exitCode = 1
        $changedCount++
    }
}

# ── Result ────────────────────────────────────────────────────────────────
$g3Reopened = ($exitCode -ne 0)
Write-Host ""
if (-not $g3Reopened) {
    Write-Host "Freeze baseline intact. No v1 bytes changed since $frozenCommit." -ForegroundColor Green
} else {
    Write-Host "[FAIL] $changedCount file(s) changed since $frozenCommit." -ForegroundColor Red
    Write-Host "       G3 must be reopened before further v1 byte changes." -ForegroundColor Red
    Write-Host "       To update the baseline after reopening G3:" -ForegroundColor Yellow
    Write-Host "         git checkout $frozenCommit -- tests/vectors/format-v1/freeze-baseline.json" -ForegroundColor Yellow
    Write-Host "         # then: set frozen_commit to new HEAD, update documentary hashes" -ForegroundColor Yellow
}

# Machine-readable marker for check-plan-ledger.ps1
Write-Host "##G3_STATUS=$(if ($g3Reopened) { 'OPEN' } else { 'FROZEN' })##"
exit $exitCode
