# Called by one final GitHub Actions workflow, no secrets, no production access.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$SingBoxExe,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
$stage = Join-Path $env:RUNNER_TEMP ('internet-pkg-' + [guid]::NewGuid().ToString('N'))
$files = @(
    @{path='internet.exe';source=$Exe},
    @{path='sing-box.exe';source=$SingBoxExe},
    @{path='windows/menu.ps1';source='windows/menu.ps1'},
    @{path='windows/configure_from_vault.py';source='windows/configure_from_vault.py'},
    @{path='vm/tools/render_runtime.py';source='vm/tools/render_runtime.py'}
)
try {
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $manifest = @()
    foreach ($file in $files) {
        $path = Join-Path $stage $file.path
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        Copy-Item -LiteralPath $file.source -Destination $path
        $manifest += @{
            path=$file.path
            size=(Get-Item -LiteralPath $path).Length
            sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
    }
    @{ schema='internet-release-v1';arch='windows-x64';files=$manifest } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding utf8
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $Output -Force
}
finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force } }
