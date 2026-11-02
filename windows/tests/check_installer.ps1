# Windows CI runner only. Explicitly scoped to a fresh C:\internet test root.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackagePath)
$ErrorActionPreference='Stop'
$root='C:\internet'
if(Test-Path -LiteralPath $root){throw 'INSTALLER_TEST_ROOT_NOT_EMPTY'}
$stage=Join-Path $env:RUNNER_TEMP ('internet-install-check-'+[guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $stage | Out-Null

    # Invalid manifest must not create an installation.
    $bad=Join-Path $stage 'bad'
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $bad
    Set-Content -LiteralPath (Join-Path $bad 'windows/menu.ps1') -Value 'corrupt' -NoNewline
    $badZip=Join-Path $stage 'invalid.zip'
    Compress-Archive -Path (Join-Path $bad '*') -DestinationPath $badZip
    $failed=$false
    try { & ./windows/install.ps1 -PackagePath $badZip | Out-Null }
    catch {
        $failed=$true
        if($_.Exception.Message -notmatch 'PACKAGE_(SHA256|SIZE)_MISMATCH') {throw}
    }
    if(-not $failed -or (Test-Path -LiteralPath $root)){throw 'INVALID_INSTALL_DID_NOT_NOOP'}
    if(Get-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\' -ErrorAction SilentlyContinue){
        throw 'INVALID_INSTALL_CREATED_TASK'
    }
    'INVALID_INSTALL_NOOP=PASS'

    & ./windows/install.ps1 -PackagePath $PackagePath | Out-Null
    $exe=Join-Path $root 'internet.exe'
    if(-not (Test-Path -LiteralPath $exe) -or
       (Test-Path -LiteralPath (Join-Path $root 'config/sing-box.json'))){
        throw 'CLEAN_INSTALL_STATE_INVALID'
    }
    $task=Get-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\' -ErrorAction Stop
    $details=[xml](Export-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\')
    if($task.State -eq 'Running' -or
       @($task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0 -or
       $task.Actions.Execute -cne 'C:\internet\sing-box.exe' -or
       $details.Task.Principals.Principal.UserId -cne 'S-1-5-18'){
        throw 'INSTALL_TASK_SCOPE_INVALID'
    }
    'OWNED_NATIVE_TASK_READY=PASS'
    $baseline=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $again=@(& ./windows/install.ps1 -PackagePath $PackagePath)
    if($again -notcontains 'INSTALL_NOOP=PASS'){throw 'REINSTALL_NOT_NOOP'}
    if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $baseline){
        throw 'REINSTALL_BINARY_CHANGED'
    }
    'FRESH_INSTALL_AND_NOOP=PASS'

    # Real stopped-restore test only on disposable CI Windows with fake auth.
    & python (Join-Path $PSScriptRoot 'check_restore.py')
    if ($LASTEXITCODE -ne 0) { throw 'U2_STOPPED_RESTORE_CI_FAILED' }

    # One ephemeral native sing-box process: local rule-set file watcher
    # really changes routing without restarting the process. No TUN/VM.
    & python (Join-Path $PSScriptRoot 'check_hot_rules.py')
    if ($LASTEXITCODE -ne 0) { throw 'U3_NATIVE_HOT_RELOAD_CI_FAILED' }

    # Generic app-name and full-path operations on disposable Windows,
    # with TUN OFF: zero production network changes.
    & python (Join-Path $PSScriptRoot 'check_generic_app.py')
    if ($LASTEXITCODE -ne 0) { throw 'U3_GENERIC_APP_CI_FAILED' }

    # The manifest is updated to reflect a defective candidate executable.
    # It passes hash checks; the CLI self-check must fail and roll back the
    # previous working EXE, without destroying its configuration.
    $broken=Join-Path $stage 'broken'
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $broken
    $exeBroken=Join-Path $broken 'internet.exe'
    Set-Content -LiteralPath $exeBroken -Value 'not-an-executable' -NoNewline
    $manifestFile=Join-Path $broken 'manifest.json'
    $manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    $entry=@($manifest.files | Where-Object { $_.path -ceq 'internet.exe' })
    if($entry.Count -ne 1){throw 'TEST_MANIFEST_INVALID'}
    $entry[0].sha256=(Get-FileHash -LiteralPath $exeBroken -Algorithm SHA256).Hash
    $entry[0].size=(Get-Item -LiteralPath $exeBroken).Length
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestFile -Encoding utf8
    $brokenZip=Join-Path $stage 'broken.zip'
    Compress-Archive -Path (Join-Path $broken '*') -DestinationPath $brokenZip
    $failed=$false
    try { & ./windows/install.ps1 -PackagePath $brokenZip | Out-Null }
    catch { $failed=$true }
    if(-not $failed){throw 'BROKEN_BINARY_NOT_REJECTED'}
    if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -cne $baseline){
        throw 'FAILED_UPDATE_DID_NOT_RECOVER'
    }
    & $exe help --json | Out-Null
    if($LASTEXITCODE -ne 0){throw 'RECOVERED_CLI_NOT_EXECUTABLE'}
    'FAILED_UPDATE_RECOVERY=PASS'

    # One disposable NTFS fixture: terminate only the subprocess we created
    # after File.Replace and prove both old backup and new destination survive.
    $atomic=Join-Path $stage 'atomic-interruption'
    New-Item -ItemType Directory -Path $atomic | Out-Null
    $oldFile=Join-Path $atomic 'installed.bin'
    $newFile=Join-Path $atomic 'candidate.bin'
    $saved=Join-Path $atomic 'previous.bin'
    $signal=Join-Path $atomic 'swapped.flag'
    [IO.File]::WriteAllBytes($oldFile,[Text.Encoding]::ASCII.GetBytes(('old-version-'*1024)))
    [IO.File]::WriteAllBytes($newFile,[Text.Encoding]::ASCII.GetBytes(('new-version-'*1024)))
    $oldHash=(Get-FileHash -LiteralPath $oldFile -Algorithm SHA256).Hash
    $newHash=(Get-FileHash -LiteralPath $newFile -Algorithm SHA256).Hash
    if($oldHash -ceq $newHash){throw 'ATOMIC_FIXTURE_INVALID'}
    $childFile=Join-Path $atomic 'replace-and-block.ps1'
    @(
        'param([string]$Candidate,[string]$Installed,[string]$Backup,[string]$Signal)',
        '$ErrorActionPreference=''Stop''',
        '[IO.File]::Replace($Candidate,$Installed,$Backup)',
        '[IO.File]::WriteAllText($Signal,''DONE'')',
        'Start-Sleep -Seconds 20'
    ) | Set-Content -LiteralPath $childFile -Encoding utf8
    $child=Start-Process -FilePath (Get-Command pwsh.exe).Source -ArgumentList @(
        '-NoProfile','-NonInteractive','-File',
        ('"'+$childFile+'"'),('"'+$newFile+'"'),('"'+$oldFile+'"'),
        ('"'+$saved+'"'),('"'+$signal+'"')
    ) -PassThru
    try {
        $until=[datetime]::UtcNow.AddSeconds(10)
        while(-not (Test-Path -LiteralPath $signal) -and [datetime]::UtcNow -lt $until) {
            if($child.HasExited){throw 'ATOMIC_CHILD_EXITED_EARLY'}
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $signal)){throw 'ATOMIC_CHILD_NOT_READY'}
        Stop-Process -Id $child.Id -Force -ErrorAction Stop
        $child.WaitForExit(5000) | Out-Null
    } finally {
        if(-not $child.HasExited){ Stop-Process -Id $child.Id -Force -ErrorAction Stop }
        $child.Dispose()
    }
    if((Get-FileHash -LiteralPath $oldFile -Algorithm SHA256).Hash -cne $newHash -or
       (Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -cne $oldHash){
        throw 'ATOMIC_PROCESS_TERMINATION_LOST_WORKING_FILE'
    }
    'ATOMIC_REPLACE_CHILD_TERMINATION=PASS'
    [IO.File]::Replace($saved,$oldFile,(Join-Path $atomic 'discarded.bin'))
    if((Get-FileHash -LiteralPath $oldFile -Algorithm SHA256).Hash -cne $oldHash) {
        throw 'ATOMIC_POST_TERMINATION_ROLLBACK_FAILED'
    }
    'ATOMIC_REPLACE_RECOVERY=PASS'

    $task=Get-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\' -ErrorAction Stop
    if($task.State -eq 'Running'){throw 'INSTALL_STARTED_DATAPLANE'}
    'FIRST_INSTALL_NO_NETWORK_PROCESS=PASS'
}
finally {
    $task=Get-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\' -ErrorAction SilentlyContinue
    if($task){
        $xml=[xml](Export-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\')
        if($task.Actions.Execute -cne 'C:\internet\sing-box.exe' -or
           $xml.Task.Principals.Principal.UserId -cne 'S-1-5-18' -or
           @($task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0){
            throw 'TEST_CLEANUP_TASK_OWNER_CONFLICT'
        }
        Unregister-ScheduledTask -TaskName INTERNET-SingBox -TaskPath '\' -Confirm:$false -ErrorAction Stop
    }
    if((Test-Path -LiteralPath (Join-Path $root '.internet-owned')) -and
       (Get-Content -LiteralPath (Join-Path $root '.internet-owned') -Raw).Trim() -ceq 'iamaman11/internet:s2-windows-x64'){
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
}