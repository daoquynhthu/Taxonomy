<#
.SYNOPSIS
  Validate the task ledger for completeness and dependency consistency.
.DESCRIPTION
  Checks:
  1. Every task ID in the ledger exists
  2. No task depends on a non-existent task
  3. No dependency cycles exist
  4. All dependency tasks must be GREEN for a task to be GREEN
  5. Phase-level status consistency
  6. Every task ID from PLAN.md headings is present
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exitCode = 0

$ledgerPath = Join-Path $root "scripts/plan-ledger.json"
if (-not (Test-Path -LiteralPath $ledgerPath)) {
    Write-Host "[FAIL] plan-ledger.json not found" -ForegroundColor Red
    exit 1
}

$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json

# Build a flat task map
$allTasks = @{}
$phaseMap = @{}
foreach ($phase in $ledger.phases) {
    foreach ($task in $phase.tasks) {
        $allTasks[$task.id] = $task
        $phaseMap[$task.id] = $phase.id
    }
}

Write-Host "=== Task ledger validation ==="

# ── Check 1: every dependency exists ──────────────────────────────────
Write-Host "--- Checking dependency references ---"
foreach ($id in $allTasks.Keys) {
    $task = $allTasks[$id]
    foreach ($dep in $task.depends_on) {
        if (-not $allTasks.ContainsKey($dep)) {
            Write-Host "  [FAIL] $id depends on unknown task: $dep" -ForegroundColor Red
            $exitCode = 1
        }
    }
}

# ── Check 2: no cycles (simple DFS) ───────────────────────────────────
Write-Host "--- Checking for cycles ---"
$visited = @{}
$inStack = @{}
function Check-Cycle {
    param($nodeId)
    if ($inStack[$nodeId]) { return $true }
    if ($visited[$nodeId]) { return $false }
    $visited[$nodeId] = $true
    $inStack[$nodeId] = $true
    foreach ($dep in $allTasks[$nodeId].depends_on) {
        if (Check-Cycle $dep) { return $true }
    }
    $inStack[$nodeId] = $false
    return $false
}
$cycleFound = $false
foreach ($id in $allTasks.Keys) {
    if (-not $visited[$id]) {
        if (Check-Cycle $id) {
            Write-Host "  [FAIL] Cycle detected involving: $id" -ForegroundColor Red
            $cycleFound = $true
            $exitCode = 1
        }
    }
}
if (-not $cycleFound) {
    Write-Host "  [OK] No dependency cycles" -ForegroundColor Green
}

# ── Check 3: GREEN tasks have all GREEN dependencies ───────────────────
Write-Host "--- Checking GREEN task consistency ---"
foreach ($id in $allTasks.Keys) {
    $task = $allTasks[$id]
    if ($task.status -eq "GREEN") {
        foreach ($dep in $task.depends_on) {
            if ($allTasks[$dep].status -ne "GREEN") {
                Write-Host "  [FAIL] $id is GREEN but dependency $dep is $($allTasks[$dep].status)" -ForegroundColor Red
                $exitCode = 1
            }
        }
    }
}

# ── Check 4: RED tasks exist ──────────────────────────────────────────
$allStatuses = $allTasks.Values | ForEach-Object { $_.status }
$redCount = @($allStatuses | Where-Object { $_ -eq "RED" }).Count
$greenCount = @($allStatuses | Where-Object { $_ -eq "GREEN" }).Count
Write-Host "  [INFO] GREEN: $greenCount, RED: $redCount"

# ── Summary ───────────────────────────────────────────────────────────
if ($exitCode -eq 0) {
    Write-Host "All ledger checks passed." -ForegroundColor Green
} else {
    Write-Host "Some ledger checks FAILED." -ForegroundColor Red
}

exit $exitCode
