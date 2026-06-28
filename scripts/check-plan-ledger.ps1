<#
.SYNOPSIS
  Validate the task ledger for completeness and dependency consistency.
.DESCRIPTION
  Checks:
  1. Every task ID from PLAN.md headings is present in the ledger
  2. No extra task IDs in the ledger that don't exist in PLAN.md
  3. No duplicate task IDs in either source
  4. Every dependency reference exists
  5. No dependency cycles exist
  6. All GREEN task dependencies are also GREEN
  7. All status values are valid (GREEN or RED)
  8. Phase-level status consistency
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exitCode = 0

# ── Parse PLAN.md for all numbered task IDs ─────────────────────────────
$planPath = Join-Path $root "docs/PLAN.md"
if (-not (Test-Path -LiteralPath $planPath)) {
    Write-Host "[FAIL] PLAN.md not found" -ForegroundColor Red
    exit 1
}

$planContent = Get-Content -LiteralPath $planPath -Raw
$planTaskIds = [System.Collections.Generic.HashSet[String]]::new()

# Match numbered task IDs from heading lines only: "### F2.1" or "### F2.1 — Title"
$pattern = [regex]::new('^#{2,3}\s+([A-Z]\d+\.\d+)', [System.Text.RegularExpressions.RegexOptions]::Multiline)
$matches = $pattern.Matches($planContent)
$duplicatesInPlan = [System.Collections.Generic.HashSet[String]]::new()
foreach ($m in $matches) {
    $id = $m.Groups[1].Value
    if (-not $planTaskIds.Add($id)) {
        Write-Host "  [FAIL] Duplicate task ID in PLAN.md: $id" -ForegroundColor Red
        $exitCode = 1
        $null = $duplicatesInPlan.Add($id)
    }
}

Write-Host "--- Plan task IDs parsed: $($planTaskIds.Count) unique tasks ---"

# ── Load ledger ─────────────────────────────────────────────────────────
$ledgerPath = Join-Path $root "scripts/plan-ledger.json"
if (-not (Test-Path -LiteralPath $ledgerPath)) {
    Write-Host "[FAIL] plan-ledger.json not found" -ForegroundColor Red
    exit 1
}

$ledger = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json

# Build flat task map from ledger
$allTasks = @{}
$phaseMap = @{}
$ledgerTaskIds = [System.Collections.Generic.HashSet[String]]::new()
$duplicatesInLedger = [System.Collections.Generic.HashSet[String]]::new()

foreach ($phase in $ledger.phases) {
    foreach ($task in $phase.tasks) {
        if (-not $ledgerTaskIds.Add($task.id)) {
            Write-Host "  [FAIL] Duplicate task ID in ledger: $($task.id)" -ForegroundColor Red
            $exitCode = 1
            $null = $duplicatesInLedger.Add($task.id)
        }
        $allTasks[$task.id] = $task
        $phaseMap[$task.id] = $phase.id
    }
}

Write-Host "=== Task ledger validation ==="

# ── Check 1: PLAN.md tasks must exist in ledger ─────────────────────────
Write-Host "--- Checking PLAN.md tasks are present in ledger ---"
$missingFromLedger = [System.Collections.Generic.List[String]]::new()
foreach ($id in $planTaskIds) {
    if (-not $allTasks.ContainsKey($id)) {
        $missingFromLedger.Add($id)
        Write-Host "  [FAIL] Task $id exists in PLAN.md but is missing from ledger" -ForegroundColor Red
        $exitCode = 1
    }
}
if ($missingFromLedger.Count -eq 0) {
    Write-Host "  [OK] All PLAN.md tasks are present in ledger" -ForegroundColor Green
}

# ── Check 2: No extra tasks in ledger ────────────────────────────────────
Write-Host "--- Checking for extra tasks in ledger ---"
$extraInLedger = [System.Collections.Generic.List[String]]::new()
foreach ($id in $ledgerTaskIds) {
    if (-not $planTaskIds.Contains($id)) {
        $extraInLedger.Add($id)
        Write-Host "  [FAIL] Task $id exists in ledger but not in PLAN.md" -ForegroundColor Red
        $exitCode = 1
    }
}
if ($extraInLedger.Count -eq 0) {
    Write-Host "  [OK] No extra tasks in ledger" -ForegroundColor Green
}

# ── Check 3: every dependency exists ──────────────────────────────────
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
if ($exitCode -eq 0 -or (-not $missingFromLedger.Count -and -not $extraInLedger.Count)) {
    # partial pass for deps depends on the ledger having correct IDs
}

# ── Check 4: no cycles (simple DFS) ───────────────────────────────────
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

# ── Check 5: All status values are valid ────────────────────────────────
Write-Host "--- Checking status values ---"
$validStatuses = @("GREEN", "RED")
$invalidStatuses = [System.Collections.Generic.List[String]]::new()
foreach ($id in $allTasks.Keys) {
    $task = $allTasks[$id]
    if ($validStatuses -notcontains $task.status) {
        $invalidStatuses.Add("$id has invalid status: $($task.status)")
        Write-Host "  [FAIL] $id has invalid status: $($task.status)" -ForegroundColor Red
        $exitCode = 1
    }
}
if ($invalidStatuses.Count -eq 0) {
    Write-Host "  [OK] All status values are valid" -ForegroundColor Green
}

# ── Check 6: GREEN tasks have all GREEN dependencies ───────────────────
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

# ── Check 7: Phase consistency ───────────────────────────────────────────
Write-Host "--- Checking phase assignment ---"
$phaseMismatched = 0
foreach ($id in $allTasks.Keys) {
    $phase = $phaseMap[$id]
    $prefix = $id -replace '\..*$', ''
    if ($phase -ne $prefix) {
        Write-Host "  [FAIL] Task $id belongs to phase $phase but prefix is $prefix" -ForegroundColor Red
        $exitCode = 1
        $phaseMismatched++
    }
}
if ($phaseMismatched -eq 0) {
    Write-Host "  [OK] All tasks belong to the correct phase" -ForegroundColor Green
}

# ── Check 8: G3_REOPENED marker consistency ───────────────────────────────
Write-Host "--- Checking G3 freeze marker consistency ---"
$f3_11 = $allTasks["F3.11"]
if ($f3_11 -ne $null) {
    $baselinePath = Join-Path $root "tests/vectors/format-v1/freeze-baseline.json"
    if (Test-Path -LiteralPath $baselinePath) {
        $baseline = Get-Content -Raw -LiteralPath $baselinePath | ConvertFrom-Json
        $frozenCommit = $baseline.frozen_commit

        # Verify frozen_commit is a valid ancestor of HEAD
        $null = git rev-parse --verify "$frozenCommit^{commit}" 2>&1
        $commitValid = ($LASTEXITCODE -eq 0)
        if ($commitValid) {
            git merge-base --is-ancestor $frozenCommit HEAD 2>$null
            $isAncestor = ($LASTEXITCODE -eq 0)
        } else {
            $isAncestor = $false
        }

        if (-not $commitValid) {
            $g3Open = $true
            Write-Host "  [WARN] frozen_commit '$frozenCommit' is not a valid git commit" -ForegroundColor Yellow
        } elseif (-not $isAncestor) {
            $g3Open = $true
            Write-Host "  [WARN] frozen_commit '$frozenCommit' is not an ancestor of HEAD" -ForegroundColor Yellow
        } else {
            # Check if any frozen file differs from frozen_commit
            $anyChanged = $false
            foreach ($section in @('source_files', 'fuzz_targets', 'fixtures')) {
                $baseline.$section.PSObject.Properties | ForEach-Object {
                    $path = if ($section -eq 'fixtures') { "tests/vectors/format-v1/$($_.Name)" } else { $_.Name }
                    git diff --quiet $frozenCommit -- $path 2>$null
                    if ($LASTEXITCODE -ne 0) { $anyChanged = $true }
                }
            }
            $g3Open = $anyChanged
        }

        $ledgerStatus = $f3_11.status
        if ($ledgerStatus -eq "GREEN" -and $g3Open) {
            Write-Host "  [FAIL] F3.11 is GREEN in ledger but G3 is OPEN (files changed since freeze)" -ForegroundColor Red
            $exitCode = 1
        } elseif ($ledgerStatus -eq "RED" -and -not $g3Open) {
            Write-Host "  [FAIL] F3.11 is RED in ledger but G3 is FROZEN (no files changed since freeze)" -ForegroundColor Red
            Write-Host "         Update F3.11 status to GREEN in plan-ledger.json" -ForegroundColor Yellow
            $exitCode = 1
        } else {
            Write-Host "  [OK] F3.11 ledger status ($ledgerStatus) matches G3_STATUS ($(if ($g3Open) {'OPEN'} else {'FROZEN'}))" -ForegroundColor Green
        }
    } else {
        Write-Host "  [WARN] freeze-baseline.json not found — skipping G3 marker check" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [WARN] Task F3.11 not found in ledger — skipping G3 marker check" -ForegroundColor Yellow
}

# ── Summary counts ─────────────────────────────────────────────────────
$allStatuses = $allTasks.Values | ForEach-Object { $_.status }
$redCount = @($allStatuses | Where-Object { $_ -eq "RED" }).Count
$greenCount = @($allStatuses | Where-Object { $_ -eq "GREEN" }).Count
Write-Host "  [INFO] GREEN: $greenCount, RED: $redCount"

# ── Exit ───────────────────────────────────────────────────────────────
if ($exitCode -eq 0) {
    Write-Host "All ledger checks passed." -ForegroundColor Green
} else {
    Write-Host "Some ledger checks FAILED." -ForegroundColor Red
}

exit $exitCode
