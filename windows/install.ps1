# INTERNET Windows release bootstrap. Delivery/validation only; Rust owns network logic.
[CmdletBinding()]
param(
    [string]$PackagePath,
    [string]$ReleaseTag = 'v0.2.0'
)
$ErrorActionPreference = 'Stop'
$root = 'C:\internet'
$marker = Join-Path $root '.internet-owned'
$owner = 'iamaman11/internet:s2-windows-x64'
$files = @('internet.exe','sing-box.exe','windows/menu.ps1',
           'windows/configure_from_vault.py','vm/tools/render_runtime.py')
$stage = Join-Path $env:TEMP ('internet-install-' + [guid]::NewGuid().ToString('N'))
$backups = @()
$written = @()
$createdRoot = $false
$success = $false
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
        [Environment]::Is64BitOperatingSystem -ne $true) {
        throw 'INTERNET_UNSUPPORTED_OS'
    }
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        throw 'INTERNET_ADMIN_REQUIRED'
    }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    if (-not $PackagePath) {
        $PackagePath = Join-Path $stage 'internet-windows-x64.zip'
        $uri = "https://github.com/iamaman11/internet/releases/download/$ReleaseTag/internet-windows-x64.zip"
        Invoke-WebRequest -Uri $uri -OutFile $PackagePath
    }
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw 'PACKAGE_NOT_FOUND'
    }
    $extract = Join-Path $stage 'package'
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $extract
    $manifest = Get-Content -LiteralPath (Join-Path $extract 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.schema -cne 'internet-release-v1' -or
        $manifest.arch -cne 'windows-x64' -or $manifest.files.Count -ne $files.Count) {
        throw 'PACKAGE_MANIFEST_INVALID'
    }
    foreach ($name in $files) {
        $entry = @($manifest.files | Where-Object { $_.path -ceq $name })
        if ($entry.Count -ne 1) { throw 'PACKAGE_FILE_LIST_INVALID' }
        $path = Join-Path $extract $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'PACKAGE_FILE_MISSING' }
        $item = Get-Item -LiteralPath $path
        if ($item.Length -ne [long]$entry[0].size -or $item.Length -le 0) {
            throw 'PACKAGE_SIZE_MISMATCH'
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($hash -cne [string]$entry[0].sha256) { throw 'PACKAGE_SHA256_MISMATCH' }
    }
    if (Test-Path -LiteralPath $root) {
        if (Test-Path -LiteralPath $marker) {
            if ((Get-Content -LiteralPath $marker -Raw).Trim() -cne $owner) {
                throw 'INSTALL_OWNER_CONFLICT'
            }
        } elseif (@(Get-ChildItem -LiteralPath $root -Force).Count -gt 0) {
            throw 'INSTALL_OWNER_CONFLICT'
        }
        if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'INSTALL_ROOT_REPARSE_FORBIDDEN'
        }
    } else {
        New-Item -ItemType Directory -Path $root | Out-Null
        $createdRoot = $true
    }
    $changed = @()
    foreach ($name in $files) {
        $dest = Join-Path $root $name
        $src = Join-Path $extract $name
        if ((Test-Path -LiteralPath $dest -PathType Leaf) -and
            (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ceq
                (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash) {
            continue
        }
        $changed += $name
    }
    if ($changed.Count -eq 0 -and (Test-Path -LiteralPath $marker)) {
        Write-Output 'INSTALL_NOOP=PASS'
        $success = $true
        return
    }
    $live = @(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'")
    if ($live.Count -gt 0 -and $changed -contains 'sing-box.exe') {
        throw 'INSTALL_RUNNING_SINGBOX_UPDATE_REFUSED'
    }
    $old = Join-Path $stage 'previous'
    New-Item -ItemType Directory -Path $old | Out-Null
    foreach ($name in $changed) {
        $dest = Join-Path $root $name
        $src = Join-Path $extract $name
        $parent = Split-Path -Parent $dest
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        $incoming = "$dest.incoming"
        if (Test-Path -LiteralPath $incoming) { throw 'INSTALL_STAGING_CONFLICT' }
        Copy-Item -LiteralPath $src -Destination $incoming
        if ((Get-FileHash -LiteralPath $incoming -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash) {
            throw 'INSTALL_STAGING_HASH_MISMATCH'
        }
        if (Test-Path -LiteralPath $dest) {
            $backup = Join-Path $old $name
            New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
            Move-Item -LiteralPath $dest -Destination $backup
            $backups += @{ dest=$dest; backup=$backup }
        }
        Move-Item -LiteralPath $incoming -Destination $dest
        $written += $dest
    }
    & (Join-Path $root 'internet.exe') help --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLED_CLI_SELF_CHECK_FAILED' }
    Set-Content -LiteralPath $marker -Value $owner -NoNewline
    Write-Output 'INSTALL_FILES=PASS'
    Write-Output 'INSTALL_NETWORK_MUTATION=NONE'
    Write-Output 'NEXT_ACTION=C:\internet\internet.exe status --json'
    $success = $true
}
finally {
    if (-not $success) {
        foreach ($path in $written) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        for ($i = $backups.Count - 1; $i -ge 0; $i--) {
            Move-Item -LiteralPath $backups[$i].backup -Destination $backups[$i].dest
        }
        if ($createdRoot -and (Test-Path -LiteralPath $root)) {
            if (@(Get-ChildItem -LiteralPath $root -Force -Recurse -File).Count -eq 0) {
                Remove-Item -LiteralPath $root -Recurse -Force
            }
        }
    }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
