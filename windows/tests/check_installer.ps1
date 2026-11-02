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