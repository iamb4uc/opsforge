#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)][string]$Platform,
    [Parameter(Position = 1, Mandatory = $true)][string]$Command,
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

function Invoke-OpsForgeScript {
    param([string]$Path)
    if ($RemainingArgs) {
        & $Path @ScriptArgs @RemainingArgs
    } else {
        & $Path @ScriptArgs
    }
}

switch ("$Platform`:$Command") {
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
        @'
Usage:
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
        exit 2
    }
}
