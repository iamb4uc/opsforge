#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)][string]$Platform,
    [Parameter(Position = 1, Mandatory = $true)][string]$Command,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArgs
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')

switch ("$Platform`:$Command") {
    'windows:triage' { & (Join-Path $Root 'scripts\windows\endpoint\Invoke-WinTriage.ps1') @RemainingArgs; break }
    'windows:persistence' { & (Join-Path $Root 'scripts\windows\persistence\Find-WinPersistence.ps1') @RemainingArgs; break }
    'windows:services' { & (Join-Path $Root 'scripts\windows\endpoint\Test-WinServiceAnomaly.ps1') @RemainingArgs; break }
    'windows:tasks' { & (Join-Path $Root 'scripts\windows\persistence\Test-WinScheduledTasks.ps1') @RemainingArgs; break }
    'windows:network' { & (Join-Path $Root 'scripts\windows\network\Get-WinNetworkExposure.ps1') @RemainingArgs; break }
    'windows:firewall' { & (Join-Path $Root 'scripts\windows\network\Test-WinFirewallExposure.ps1') @RemainingArgs; break }
    'windows:defender' { & (Join-Path $Root 'scripts\windows\hardening\Test-WinDefenderStatus.ps1') @RemainingArgs; break }
    'windows:privilege' { & (Join-Path $Root 'scripts\windows\hardening\Test-WinPrivilegeSurface.ps1') @RemainingArgs; break }
    'windows:timeline' { & (Join-Path $Root 'scripts\windows\forensic\New-WinEventTimeline.ps1') @RemainingArgs; break }
    'windows:log-tampering' { & (Join-Path $Root 'scripts\windows\forensic\Test-WinLogTampering.ps1') @RemainingArgs; break }
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
