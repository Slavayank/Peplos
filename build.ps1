param(
    [switch]$Sign,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$SignTool = 'signtool.exe'
)
$ErrorActionPreference = 'Stop'
$target = 'x86_64-pc-windows-msvc'
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
$releaseExe = Join-Path $PSScriptRoot "target\$target\release\peplos.exe"
$outputExe = Join-Path $PSScriptRoot 'Peplos.exe'
if (!(Test-Path -LiteralPath $cargo)) { $cargo = (Get-Command cargo.exe -ErrorAction Stop).Source }
if ($Sign -and [string]::IsNullOrWhiteSpace($CertificateThumbprint)) { throw 'Specify -CertificateThumbprint for an installed code-signing certificate.' }
& $cargo build --locked --release --target $target
if ($LASTEXITCODE -ne 0) { throw "Rust build failed with exit code $LASTEXITCODE" }
Copy-Item -LiteralPath $releaseExe -Destination $outputExe -Force
if ($Sign) {
    & $SignTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $outputExe
    if ($LASTEXITCODE -ne 0) { throw 'Code signing failed; do not distribute Peplos.exe.' }
    & $SignTool verify /pa /all /v $outputExe
    if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed; do not distribute Peplos.exe.' }
}
$hash = Get-FileHash -LiteralPath $outputExe -Algorithm SHA256
Set-Content -LiteralPath (Join-Path $PSScriptRoot 'Peplos.exe.sha256') -Value "$($hash.Hash.ToLowerInvariant())  Peplos.exe" -Encoding ascii
Write-Output "Built $outputExe; SHA-256: $($hash.Hash)"
