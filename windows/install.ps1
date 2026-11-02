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
           'windows/configure_from_vault.py','windows/proxies.py','vm/tools/render_runtime.py')
$stage = Join-Path $env:TEMP ('internet-install-' + [guid]::NewGuid().ToString('N'))
$backups = @()
$written = @()
$createdRoot = $false
$success = $false
$createdTask = $false
$taskName = 'INTERNET-SingBox'
function Test-InternetOwnedTask {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    $actions = @($task.Actions | Where-Object { $null -ne $_ })
    $triggers = @($task.Triggers | Where-Object { $null -ne $_ })
    $xml = [xml](Export-ScheduledTask -TaskName $taskName -TaskPath '\')
    $expected = Join-Path $root 'sing-box.exe'
    $arguments = 'run -c "C:\internet\config\sing-box.json"'
    if ($actions.Count -ne 1 -or $triggers.Count -ne 0 -or
        $actions[0].Execute -cne $expected -or
        $actions[0].Arguments -cne $arguments -or
        $actions[0].WorkingDirectory -cne $root -or
        $xml.Task.Principals.Principal.UserId -cne 'S-1-5-18' -or
        $xml.Task.Principals.Principal.RunLevel -cne 'HighestAvailable' -or
        $task.Description -cne 'INTERNET owned sing-box (manual start)') {
        throw 'TASK_OWNER_CONFLICT'
    }
    return $true
}
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
    # File.Replace needs the backup on the same NTFS volume as the owned root.
    # Refuse a cross-volume temp directory rather than unsafe rename windows.
    if ([IO.Path]::GetPathRoot($stage) -cne [IO.Path]::GetPathRoot($root)) {
        throw 'INSTALL_TEMP_VOLUME_MISMATCH'
    }
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
    # Validate the candidate CLI before replacing a working executable.
    # A hard interruption after an atomic replacement then leaves a runnable
    # old or new CLI, not a binary that failed its own basic self-check.
    & (Join-Path $extract 'internet.exe') help --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'PACKAGE_CLI_SELF_CHECK_FAILED' }
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
    $taskOwned = Test-InternetOwnedTask
    if ($changed.Count -eq 0 -and (Test-Path -LiteralPath $marker) -and $taskOwned) {
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
            # NTFS atomic replacement: the destination is never absent while
            # a running CLI update swaps the old and candidate file.
            [IO.File]::Replace($incoming, $dest, $backup)
            $backups += @{ dest=$dest; backup=$backup }
        } else {
            Move-Item -LiteralPath $incoming -Destination $dest
            $written += $dest
        }
    }
    & (Join-Path $root 'internet.exe') help --json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'INSTALLED_CLI_SELF_CHECK_FAILED' }
    # The existing Windows Task Scheduler is the sole persistent lifecycle owner.
    # Registration happens once at installation, never during a CLI start command.
    # There are no triggers: installation cannot start or reroute network traffic.
    if (-not $taskOwned) {
        $action = New-ScheduledTaskAction -Execute (Join-Path $root 'sing-box.exe') -Argument 'run -c "C:\internet\config\sing-box.json"' -WorkingDirectory $root
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -Description 'INTERNET owned sing-box (manual start)' -ErrorAction Stop | Out-Null
        $createdTask = $true
        if (-not (Test-InternetOwnedTask)) { throw 'TASK_INSTALL_READBACK_FAILED' }
    }
    Set-Content -LiteralPath $marker -Value $owner -NoNewline
    Write-Output 'INSTALL_FILES=PASS'
    Write-Output 'INSTALL_NETWORK_MUTATION=NONE'
    Write-Output 'NEXT_ACTION=C:\internet\internet.exe status --json'
    $success = $true
}
finally {
    if (-not $success) {
        if ($createdTask) {
            # Roll back only the task registered by this exact attempt.
            if (Test-InternetOwnedTask) {
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
            }
        }
        foreach ($path in $written) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        }
        for ($i = $backups.Count - 1; $i -ge 0; $i--) {
            $oldFile = $backups[$i].backup
            $dest = $backups[$i].dest
            if (Test-Path -LiteralPath $oldFile) {
                if (Test-Path -LiteralPath $dest) {
                    # Keep the displaced candidate only inside this disposable installer stage.
                    $discarded = "$oldFile.discarded"
                    if (Test-Path -LiteralPath $discarded) { throw 'INSTALL_ROLLBACK_STAGING_CONFLICT' }
                    [IO.File]::Replace($oldFile, $dest, $discarded)
                } else {
                    Move-Item -LiteralPath $oldFile -Destination $dest
                }
            }
        }
        if ($createdRoot -and (Test-Path -LiteralPath $root)) {
            if (@(Get-ChildItem -LiteralPath $root -Force -Recurse -File).Count -eq 0) {
                Remove-Item -LiteralPath $root -Recurse -Force
            }
        }
    }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}