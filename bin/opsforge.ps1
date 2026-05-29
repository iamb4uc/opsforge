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

function Get-LatestOutputDirectory {
    param([string]$Base, [string]$ScriptName)

    Get-ChildItem -Path $Base -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*-$ScriptName-*" } |
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

function Invoke-WindowsAll {
    $outputRoot = Get-OutputRoot
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    $ok = $true

    if (-not (Invoke-AllOne -Name 'triage' -ScriptName 'Invoke-WinTriage' -Arguments @('windows','triage') -OutputRoot $outputRoot)) { $ok = $false }
    if (-not (Invoke-AllOne -Name 'persistence' -ScriptName 'Find-WinPersistence' -Arguments @('windows','persistence') -OutputRoot $outputRoot)) { $ok = $false }
    if (-not (Invoke-AllOne -Name 'tasks' -ScriptName 'Test-WinScheduledTasks' -Arguments @('windows','tasks') -OutputRoot $outputRoot)) { $ok = $false }
    if (-not (Invoke-AllOne -Name 'network' -ScriptName 'Get-WinNetworkExposure' -Arguments @('windows','network') -OutputRoot $outputRoot)) { $ok = $false }
    if (-not (Invoke-AllOne -Name 'timeline' -ScriptName 'New-WinEventTimeline' -Arguments @('windows','timeline') -OutputRoot $outputRoot)) { $ok = $false }

    if (-not $ok) {
        exit 1
    }
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
