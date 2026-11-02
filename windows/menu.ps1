# Thin PowerShell entrypoint, no second writer or network logic.
$ErrorActionPreference = 'Stop'
$exe = 'C:\internet\internet.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'INTERNET_NOT_INSTALLED: C:\internet\internet.exe'
}
& $exe @args
exit $LASTEXITCODE
