<#
.SYNOPSIS
  Verify crate dependency direction matches the approved graph.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exitCode = 0

$allowedEdges = @{
    "eternal-format" = @()
    "eternal-store"  = @("eternal-format")
    "eternal-crypto" = @("eternal-format")
    "eternal-core"   = @("eternal-format", "eternal-store", "eternal-crypto")
    "eternal-net"    = @("eternal-format", "eternal-core")
    "eternal-cli"    = @("eternal-core", "eternal-net")
}

$allCrates = $allowedEdges.Keys

Write-Host "=== Checking crate dependency directions ==="

$depMap = @{}
foreach ($crate in $allCrates) {
    $cargoPath = Join-Path (Join-Path (Join-Path $root "crates") $crate) "Cargo.toml"
    if (-not (Test-Path -LiteralPath $cargoPath)) {
        Write-Host "  [FAIL] Cargo.toml not found for $crate" -ForegroundColor Red
        $exitCode = 1
        continue
    }

    # Read all lines, find [dependencies] section, collect until next [section]
    $lines = Get-Content -LiteralPath $cargoPath
    $inDeps = $false
    $depLines = @()
    foreach ($line in $lines) {
        if ($line -match '^\[dependencies\]') {
            $inDeps = $true
            continue
        }
        if ($inDeps) {
            if ($line -match '^\[|^$') {
                # Next section or blank line ends [dependencies]
                # But blank lines inside [dependencies] can exist, keep going
                if ($line -match '^\[' -and $line -notmatch '^\[dependencies\]') {
                    break
                }
            }
            $depLines += $line
        }
    }

    $depSection = $depLines -join "`n"
    $actualDeps = @()
    foreach ($ec in $allCrates) {
        if ($depSection -match [regex]::Escape($ec)) { $actualDeps += $ec }
    }
    $depMap[$crate] = $actualDeps

    $badDeps = $actualDeps | Where-Object { $_ -notin $allowedEdges[$crate] }
    if ($badDeps.Count -eq 0) {
        Write-Host "  [OK] $crate → $($actualDeps -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $crate → $($badDeps -join ', ') (forbidden)" -ForegroundColor Red
        Write-Host "    Allowed: $($allowedEdges[$crate] -join ', ')"
        $exitCode = 1
    }
}

if ($exitCode -eq 0) {
    Write-Host "All dependency direction checks passed." -ForegroundColor Green
} else {
    Write-Host "Some dependency checks FAILED." -ForegroundColor Red
}
exit $exitCode
