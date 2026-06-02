#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Platform,
    [Parameter(Position = 1)][string]$Command,
    [string]$OutputPath,
    [switch]$Json,
    [switch]$Markdown,
    [switch]$Quiet,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArgs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$ScriptArgs = @{}
if ($OutputPath) { $ScriptArgs.OutputPath = $OutputPath }
if ($Json) { $ScriptArgs.Json = $true }
if ($Markdown) { $ScriptArgs.Markdown = $true }
if ($Quiet) { $ScriptArgs.Quiet = $true }

function Show-Usage {
    @'
Usage:
  .\bin\opsforge.ps1 doctor
  .\bin\opsforge.ps1 windows doctor
  .\bin\opsforge.ps1 windows quick -OutputPath .\output -Json -Markdown
  .\bin\opsforge.ps1 windows ir -OutputPath .\output -Json -Markdown
  .\bin\opsforge.ps1 windows full -OutputPath .\output -Json -Markdown
  .\bin\opsforge.ps1 windows all -OutputPath .\output -Json -Markdown
  .\bin\opsforge.ps1 windows triage -OutputPath .\output
  .\bin\opsforge.ps1 windows persistence -OutputPath .\output
  .\bin\opsforge.ps1 windows services -OutputPath .\output
  .\bin\opsforge.ps1 windows tasks -OutputPath .\output
  .\bin\opsforge.ps1 windows network -OutputPath .\output
  .\bin\opsforge.ps1 windows firewall -OutputPath .\output
  .\bin\opsforge.ps1 windows defender -OutputPath .\output
  .\bin\opsforge.ps1 windows privilege -OutputPath .\output
  .\bin\opsforge.ps1 windows timeline -OutputPath .\output
  .\bin\opsforge.ps1 windows log-tampering -OutputPath .\output
'@ | Write-Host
}

function Invoke-OpsForgeScript {
    param([string]$Path)
    if ($RemainingArgs) {
        & $Path @ScriptArgs @RemainingArgs
    } else {
        & $Path @ScriptArgs
    }
}

function Test-CommandAvailable {
    param([string]$Name, [bool]$Required)

    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        Write-Host ("ok       {0}" -f $Name)
        return $true
    }

    if ($Required) {
        Write-Host ("missing  {0}" -f $Name)
        return $false
    }

    Write-Host ("optional {0} missing" -f $Name)
    return $true
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-OpsForgeDoctor {
    $failures = 0
    $targetOutput = if ($OutputPath) { $OutputPath } else { Join-Path $Root 'output' }

    Write-Host 'opsforge doctor'
    Write-Host ("root: {0}" -f $Root)
    Write-Host ("powershell: {0}" -f $PSVersionTable.PSVersion)
    Write-Host ("execution policy: {0}" -f (Get-ExecutionPolicy))
    if (Test-IsAdmin) {
        Write-Host 'privilege: administrator'
    } else {
        Write-Host 'privilege: normal user'
    }
    Write-Host ''

    foreach ($commandName in @(
        'Get-Process',
        'Get-Service',
        'Get-WinEvent',
        'Get-ScheduledTask',
        'Get-NetTCPConnection',
        'Get-NetFirewallRule'
    )) {
        if (-not (Test-CommandAvailable -Name $commandName -Required $true)) {
            $failures++
        }
    }

    Test-CommandAvailable -Name 'Get-MpComputerStatus' -Required $false | Out-Null

    $parent = Split-Path -Parent $targetOutput
    if ((Test-Path $targetOutput -PathType Container) -and
        -not ((Get-Item $targetOutput).Attributes -band [IO.FileAttributes]::ReadOnly)) {
        Write-Host ("ok       writable output: {0}" -f $targetOutput)
    } elseif ((Test-Path $parent -PathType Container) -and
        -not ((Get-Item $parent).Attributes -band [IO.FileAttributes]::ReadOnly)) {
        Write-Host ("ok       output parent writable: {0}" -f $parent)
    } else {
        Write-Host ("warning  output path is not writable: {0}" -f $targetOutput)
    }

    if ($failures -gt 0) {
        exit 1
    }
}

function Get-OutputRoot {
    if ($OutputPath) {
        return $OutputPath
    }
    return (Join-Path $Root 'output')
}

function Get-SafeHostname {
    $name = $env:COMPUTERNAME
    if (-not $name) { $name = [System.Net.Dns]::GetHostName() }
    if (-not $name) { $name = 'unknown-host' }
    return ($name -replace '[^A-Za-z0-9._-]', '_')
}

function Get-LatestOutputDirectory {
    param([string]$Base, [string]$ScriptName)

    Get-ChildItem -Path $Base -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*-$ScriptName-*" } |
        Sort-Object LastWriteTime |
        Select-Object -Last 1 -ExpandProperty FullName
}

function Get-LatestProfileDirectory {
    param([string]$Base, [string]$Profile)

    Get-ChildItem -Path $Base -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "opsforge-windows-$Profile-*" } |
        Sort-Object LastWriteTime |
        Select-Object -Last 1 -ExpandProperty FullName
}

function Test-OutputContract {
    param([string]$OutputDirectory)

    foreach ($entry in @('raw','normalized','report.md','findings.json','summary.txt')) {
        $path = Join-Path $OutputDirectory $entry
        if (-not (Test-Path $path)) {
            throw "missing output contract path: $path"
        }
    }

    Get-Content -Raw -Path (Join-Path $OutputDirectory 'findings.json') |
        ConvertFrom-Json |
        Out-Null
}

function Invoke-AllOne {
    param(
        [string]$Name,
        [string]$ScriptName,
        [string[]]$Arguments,
        [string]$OutputRoot
    )

    $failed = $false
    Write-Host ("[opsforge] running {0}" -f $Name)
    try {
        $wrapper = Join-Path $Root 'bin\opsforge.ps1'
        & $wrapper @Arguments -OutputPath $OutputRoot -Json:$Json -Markdown:$Markdown -Quiet:$Quiet
        $exitCode = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            $failed = $true
            Write-Host ("[opsforge] failed: {0} exited with {1}" -f $Name, $exitCode)
        }
    } catch {
        $failed = $true
        Write-Host ("[opsforge] failed: {0}: {1}" -f $Name, $_.Exception.Message)
    }

    $outDir = Get-LatestOutputDirectory -Base $OutputRoot -ScriptName $ScriptName
    if (-not $outDir) {
        Write-Host ("[opsforge] failed: {0} did not create output" -f $Name)
        return $false
    }

    Write-Host ("[opsforge] output: {0}" -f $outDir)
    try {
        Test-OutputContract -OutputDirectory $outDir
    } catch {
        Write-Host ("[opsforge] failed: {0} output contract failed: {1}" -f $Name, $_.Exception.Message)
        return $false
    }

    return (-not $failed)
}

function New-ProfileArguments {
    param([string]$OutputRoot)

    $args = @{
        OutputPath = $OutputRoot
    }
    if ($Json) { $args.Json = $true }
    if ($Markdown) { $args.Markdown = $true }
    if ($Quiet) { $args.Quiet = $true }
    return $args
}

function New-ProfileResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Output,
        [string]$Contract
    )

    [pscustomobject]@{
        name = $Name
        status = $Status
        output = $Output
        contract = $Contract
    }
}

function Invoke-ProfileScript {
    param(
        [string]$Name,
        [string]$ScriptName,
        [string]$ScriptPath,
        [string]$OutputRoot,
        [hashtable]$ProfileArgs
    )

    $failed = $false
    Write-Host ("[opsforge] running {0}" -f $Name)
    try {
        & $ScriptPath @ProfileArgs
        $exitCode = Get-Variable -Name LASTEXITCODE -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $exitCode -and $exitCode -ne 0) {
            $failed = $true
            Write-Host ("[opsforge] failed: {0} exited with {1}" -f $Name, $exitCode)
        }
    } catch {
        $failed = $true
        Write-Host ("[opsforge] failed: {0}: {1}" -f $Name, $_.Exception.Message)
    }

    $outDir = Get-LatestOutputDirectory -Base $OutputRoot -ScriptName $ScriptName
    if (-not $outDir) {
        Write-Host ("[opsforge] failed: {0} did not create output" -f $Name)
        return (New-ProfileResult -Name $Name -Status 'failed' -Output '' -Contract 'missing-output')
    }

    Write-Host ("[opsforge] output: {0}" -f $outDir)
    try {
        Test-OutputContract -OutputDirectory $outDir
    } catch {
        Write-Host ("[opsforge] failed: {0} output contract failed: {1}" -f $Name, $_.Exception.Message)
        return (New-ProfileResult -Name $Name -Status 'failed' -Output $outDir -Contract 'failed')
    }

    if ($failed) {
        return (New-ProfileResult -Name $Name -Status 'failed' -Output $outDir -Contract 'passed')
    }

    return (New-ProfileResult -Name $Name -Status 'passed' -Output $outDir -Contract 'passed')
}

function Write-WindowsProfileSummary {
    param(
        [string]$ParentDir,
        [string]$Profile,
        [string]$HostName,
        [datetime]$StartedAt,
        [datetime]$EndedAt,
        [object[]]$Results,
        [object[]]$Skipped
    )

    $failed = @($Results | Where-Object { $_.status -ne 'passed' }).Count
    $summaryMd = Join-Path $ParentDir 'run-summary.md'
    $summaryJson = Join-Path $ParentDir 'run-summary.json'
    $lines = @(
        "# opsforge Windows $Profile",
        '',
        "Host: $HostName",
        '',
        ('Started: {0}' -f $StartedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
        '',
        ('Ended: {0}' -f $EndedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
        '',
        "Failed tools: $failed",
        '',
        '## Tools',
        '',
        '| Tool | Status | Contract | Output |',
        '| --- | --- | --- | --- |'
    )

    foreach ($result in $Results) {
        $output = if ($result.output) { $result.output } else { 'none' }
        $lines += ('| {0} | {1} | {2} | {3} |' -f $result.name, $result.status, $result.contract, $output)
    }

    $lines += ''
    $lines += '## Skipped'
    $lines += ''
    if (@($Skipped).Count -eq 0) {
        $lines += 'None.'
    } else {
        foreach ($item in $Skipped) {
            $lines += ('- {0}: {1}' -f $item.name, $item.reason)
        }
    }

    $lines += ''
    $lines += '## Next Steps'
    $lines += ''
    if ($failed -gt 0) {
        $lines += '- Review failed tool output and rerun that tool directly.'
    } else {
        $lines += '- Review findings.json and report.md files for each tool output.'
    }

    Set-Content -Path $summaryMd -Value $lines -Encoding UTF8

    [pscustomobject]@{
        host = $HostName
        profile = $Profile
        started_at = $StartedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ended_at = $EndedAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        failed_tools = $failed
        tools = $Results
        skipped = $Skipped
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryJson -Encoding UTF8
}

function Invoke-WindowsProfile {
    param([string]$Profile)

    $outputRoot = Get-OutputRoot
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

    $hostName = Get-SafeHostname
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $parentDir = Join-Path $outputRoot "opsforge-windows-$Profile-$hostName-$stamp"
    New-Item -ItemType Directory -Force -Path $parentDir | Out-Null

    $profileArgs = New-ProfileArguments -OutputRoot $parentDir
    $startedAt = Get-Date
    $results = @()
    $skipped = @()

    $scripts = @{
        triage = @{ Path = Join-Path $Root 'scripts\windows\endpoint\Invoke-WinTriage.ps1'; ScriptName = 'Invoke-WinTriage' }
        persistence = @{ Path = Join-Path $Root 'scripts\windows\persistence\Find-WinPersistence.ps1'; ScriptName = 'Find-WinPersistence' }
        tasks = @{ Path = Join-Path $Root 'scripts\windows\persistence\Test-WinScheduledTasks.ps1'; ScriptName = 'Test-WinScheduledTasks' }
        network = @{ Path = Join-Path $Root 'scripts\windows\network\Get-WinNetworkExposure.ps1'; ScriptName = 'Get-WinNetworkExposure' }
        timeline = @{ Path = Join-Path $Root 'scripts\windows\forensic\New-WinEventTimeline.ps1'; ScriptName = 'New-WinEventTimeline' }
        services = @{ Path = Join-Path $Root 'scripts\windows\endpoint\Test-WinServiceAnomaly.ps1'; ScriptName = 'Test-WinServiceAnomaly' }
        firewall = @{ Path = Join-Path $Root 'scripts\windows\network\Test-WinFirewallExposure.ps1'; ScriptName = 'Test-WinFirewallExposure' }
        defender = @{ Path = Join-Path $Root 'scripts\windows\hardening\Test-WinDefenderStatus.ps1'; ScriptName = 'Test-WinDefenderStatus' }
        privilege = @{ Path = Join-Path $Root 'scripts\windows\hardening\Test-WinPrivilegeSurface.ps1'; ScriptName = 'Test-WinPrivilegeSurface' }
        logtampering = @{ Path = Join-Path $Root 'scripts\windows\forensic\Test-WinLogTampering.ps1'; ScriptName = 'Test-WinLogTampering' }
    }

    switch ($Profile) {
        'quick' { $toolNames = @('triage','tasks','network') }
        'ir' { $toolNames = @('triage','persistence','tasks','network','timeline') }
        'full' { $toolNames = @('triage','persistence','services','tasks','network','firewall','defender','privilege','timeline','logtampering') }
        'all' { $toolNames = @('triage','persistence','tasks','network','timeline') }
        default {
            Write-Host "unknown windows profile: $Profile"
            exit 2
        }
    }

    foreach ($toolName in $toolNames) {
        $tool = $scripts[$toolName]
        if (-not (Test-Path $tool.Path)) {
            $skipped += [pscustomobject]@{ name = $toolName; reason = 'script missing' }
            Write-Host ("[opsforge] skipped {0}: script missing" -f $toolName)
            continue
        }
        $results += Invoke-ProfileScript -Name $toolName -ScriptName $tool.ScriptName -ScriptPath $tool.Path -OutputRoot $parentDir -ProfileArgs $profileArgs
    }

    $endedAt = Get-Date
    Write-WindowsProfileSummary -ParentDir $parentDir -Profile $Profile -HostName $hostName -StartedAt $startedAt -EndedAt $endedAt -Results $results -Skipped $skipped
    Write-Host ("[opsforge] profile summary: {0}" -f (Join-Path $parentDir 'run-summary.md'))

    if (@($results | Where-Object { $_.status -ne 'passed' }).Count -gt 0) {
        exit 1
    }
}

function Invoke-WindowsAll {
    Invoke-WindowsProfile -Profile 'all'
}

if ($Platform -in @('-h','--help') -or -not $Platform) {
    Show-Usage
    exit 0
}

if ($Platform -eq 'doctor') {
    Invoke-OpsForgeDoctor
    exit 0
}

switch ("$Platform`:$Command") {
    'windows:doctor' { Invoke-OpsForgeDoctor; break }
    'windows:quick' { Invoke-WindowsProfile -Profile 'quick'; break }
    'windows:ir' { Invoke-WindowsProfile -Profile 'ir'; break }
    'windows:full' { Invoke-WindowsProfile -Profile 'full'; break }
    'windows:all' { Invoke-WindowsAll; break }
    'windows:triage' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\endpoint\Invoke-WinTriage.ps1'); break }
    'windows:persistence' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\persistence\Find-WinPersistence.ps1'); break }
    'windows:services' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\endpoint\Test-WinServiceAnomaly.ps1'); break }
    'windows:tasks' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\persistence\Test-WinScheduledTasks.ps1'); break }
    'windows:network' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\network\Get-WinNetworkExposure.ps1'); break }
    'windows:firewall' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\network\Test-WinFirewallExposure.ps1'); break }
    'windows:defender' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\hardening\Test-WinDefenderStatus.ps1'); break }
    'windows:privilege' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\hardening\Test-WinPrivilegeSurface.ps1'); break }
    'windows:timeline' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\forensic\New-WinEventTimeline.ps1'); break }
    'windows:log-tampering' { Invoke-OpsForgeScript (Join-Path $Root 'scripts\windows\forensic\Test-WinLogTampering.ps1'); break }
    default {
        Show-Usage
        exit 2
    }
}
