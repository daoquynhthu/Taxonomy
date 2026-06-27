<#
.SYNOPSIS
  Generate binary format-v1 fixture files from the hex-encoded golden vectors
  in tests/vectors/format-v1/format-v1.json.

  Independent fixture generator for PLAN.md F3.9.
  Does NOT import any EternalCore production code.

  Run: pwsh -File scripts/gen-format-v1-fixtures.ps1
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root "tests/vectors/format-v1"
$jsonPath = Join-Path $outDir "format-v1.json"

if (-not (Test-Path -LiteralPath $jsonPath)) {
    Write-Host "ERROR: format-v1.json not found at $jsonPath" -ForegroundColor Red; exit 1
}

$json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json

$hexFixtures = @{
    "canonical-cbor-v1.bin"              = "canonical_cbor_hex"
    "ref-update-payload-v1.bin"          = "ref_payload_hex"
    "ref-update-envelope-v1.bin"         = "ref_env_hex"
    "content-manifest-v1.bin"            = "manifest_hex"
    "repo-commit-payload-v1.bin"         = "commit_payload_hex"
    "encoded-chunk-v1.bin"               = "encoded_chunk_hex"
    "encrypted-chunk-ciphertext-v1.bin"  = "ciphertext"
}

function Write-HexFile {
    param([string]$Path, [string]$Hex)
    $hex = $Hex.Trim()
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
    Write-Host "  [OK] $Path ($($bytes.Length) bytes)" -ForegroundColor Green
}

function Write-BytesFile {
    param([string]$Path, [byte[]]$Bytes)
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    Write-Host "  [OK] $Path ($($Bytes.Length) bytes)" -ForegroundColor Green
}

function Add-InvalidFixture {
    param([string]$SrcName, [string]$DstName, [scriptblock]$Mutate)
    $srcPath = Join-Path $outDir $SrcName
    $dstPath = Join-Path $outDir $DstName
    if (-not (Test-Path -LiteralPath $srcPath)) {
        Write-Host "  [SKIP] $DstName — source $SrcName not found" -ForegroundColor DarkYellow; return
    }
    $srcBytes = [System.IO.File]::ReadAllBytes($srcPath)
    $outBytes = & $Mutate $srcBytes
    Write-BytesFile -Path $dstPath -Bytes $outBytes
}

Write-Host "=== Generating format-v1 binary fixtures ===" -ForegroundColor Cyan
Write-Host "  Source: $jsonPath`n"

Write-Host "-- Valid fixtures --" -ForegroundColor Yellow
foreach ($kv in $hexFixtures.GetEnumerator()) {
    $filename = $kv.Key; $field = $kv.Value; $hex = $json.$field
    if (-not $hex) { Write-Host "  [SKIP] $filename — field '$field' not found" -ForegroundColor DarkYellow; continue }
    Write-HexFile -Path (Join-Path $outDir $filename) -Hex $hex
}

Write-Host "`n-- Invalid (corrupted) fixtures --" -ForegroundColor Yellow

# 1. CBOR with duplicate map key: map(3), {0:1, 0:2, 1:3}
Write-BytesFile -Path (Join-Path $outDir "cbor-invalid-duplicate-key.bin") -Bytes @(0xa3, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03)

# 2. Trailing garbage after valid canonical CBOR
Add-InvalidFixture "canonical-cbor-v1.bin" "canonical-cbor-v1-invalid-trailing.bin" { $args[0] + [byte[]]@(0xde, 0xad, 0xbe, 0xef) }

# 3. Truncated canonical CBOR
Add-InvalidFixture "canonical-cbor-v1.bin" "canonical-cbor-v1-invalid-truncated.bin" { $b = $args[0]; if ($b.Length -gt 5) { $b[0..($b.Length - 6)] } else { @() } }

# 4. Segment header with corrupted magic
Add-InvalidFixture "segment-header-v1.bin" "segment-header-v1-invalid-magic.bin" { $b = $args[0].Clone(); if ($b.Length -ge 8) { $b[0] = 0x00 }; $b }

# 5. Segment header with corrupted CRC
Add-InvalidFixture "segment-header-v1.bin" "segment-header-v1-invalid-crc.bin" { $b = $args[0].Clone(); if ($b.Length -ge 62) { $b[61] = $b[61] -bxor 0xff }; $b }

# 6. Truncated StoreManifest CBOR
Add-InvalidFixture "store-manifest-v1.cbor" "store-manifest-v1-invalid-truncated.bin" { $b = $args[0]; if ($b.Length -gt 20) { $b[0..($b.Length - 21)] } else { @() } }

# 7. StoreManifest with corrupted first CBOR byte
Add-InvalidFixture "store-manifest-v1.cbor" "store-manifest-v1-invalid-corrupted.bin" { $b = $args[0].Clone(); if ($b.Length -ge 1) { $b[0] = 0xff }; $b }

# 8. Pack with corrupted trailer checksum (last byte flipped)
Add-InvalidFixture "pack-v1.pack" "pack-v1-invalid-trailer.bin" { $b = $args[0].Clone(); if ($b.Length -ge 1) { $b[$b.Length - 1] = $b[$b.Length - 1] -bxor 0xff }; $b }

# 9. Index with zeroed checksum (last 32 bytes cleared)
Add-InvalidFixture "pack-v1.idx" "pack-v1-idx-invalid-checksum.bin" { $b = $args[0].Clone(); if ($b.Length -ge 32) { for ($i = $b.Length - 32; $i -lt $b.Length; $i++) { $b[$i] = 0 } }; $b }

# 10. Index truncated (chop last 100 bytes)
Add-InvalidFixture "pack-v1.idx" "pack-v1-idx-invalid-truncated.bin" { $b = $args[0]; if ($b.Length -gt 100) { $b[0..($b.Length - 101)] } else { @() } }

Write-Host "`nDone." -ForegroundColor Cyan
