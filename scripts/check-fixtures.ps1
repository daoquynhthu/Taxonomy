<#
.SYNOPSIS
  Verify fixture files match their recorded SHA-256 checksums.
  Usage: scripts/check-fixtures [[-ManifestPath] <string>]
  Default: tests/vectors/format-v1/manifest.json
#>

param(
    [string]$ManifestPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $ManifestPath) {
    $ManifestPath = Join-Path $root "tests/vectors/format-v1/manifest.json"
}
elseif (-not [System.IO.Path]::IsPathRooted($ManifestPath)) {
    $ManifestPath = Join-Path $root $ManifestPath
}

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Host "Manifest not found: $ManifestPath" -ForegroundColor Red
    exit 1
}

$manifestJson = Get-Content -LiteralPath $ManifestPath -Raw
$manifest = $manifestJson | ConvertFrom-Json
$fixtureDir = Split-Path -Parent $ManifestPath
$exitCode = 0

Write-Host "=== Fixture checksum verification ==="
Write-Host "  Manifest: $ManifestPath"

foreach ($entry in $manifest.fixtures) {
    $fixturePath = Join-Path $fixtureDir $entry.filename
    if (-not (Test-Path -LiteralPath $fixturePath)) {
        Write-Host "  [FAIL] Missing file: $($entry.filename)" -ForegroundColor Red
        $exitCode = 1
        continue
    }

    $actualHash = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedHash = $entry.sha256.ToLowerInvariant()
    $actualLen = (Get-Item -LiteralPath $fixturePath).Length
    $expectedLen = $entry.length

    $hashOk = ($actualHash -eq $expectedHash)
    $lenOk = ($actualLen -eq $expectedLen)

    if ($hashOk -and $lenOk) {
        Write-Host "  [OK] $($entry.filename)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($entry.filename)" -ForegroundColor Red
        if (-not $lenOk) {
            Write-Host "    Length: expected=$expectedLen actual=$actualLen"
        }
        if (-not $hashOk) {
            Write-Host "    SHA256 mismatch:"
            Write-Host "      expected=$expectedHash"
            Write-Host "      actual=  $actualHash"
        }
        $exitCode = 1
    }
}

if ($exitCode -eq 0) {
    Write-Host "All fixture checksums match." -ForegroundColor Green
} else {
    Write-Host "Some fixtures FAILED verification." -ForegroundColor Red
}

exit $exitCode
