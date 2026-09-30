#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) 'output'),
    [switch]$Json,
    [switch]$Markdown,
    [switch]$Quiet
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
. (Join-Path $RepoRoot 'lib\windows\Common.ps1')
. (Join-Path $RepoRoot 'lib\windows\Logging.ps1')

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Invoke-WinTriage'
$findings = New-Object System.Collections.Generic.List[object]

function Save-RawJson {
    param([string]$Name, [scriptblock]$Collector)
    try {
        $records = & $Collector
    } catch {
        "Collector $Name failed: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir "raw\$Name.error.txt")
        return
    }
    if ($null -eq $records) { $records = @() }
    ConvertTo-Json -InputObject @($records) -Depth 7 -WarningAction Stop | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir "raw\$Name.json")
}

Save-RawJson 'os-version' { Get-CimInstance Win32_OperatingSystem | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'local-users' { Get-LocalUser | Select-Object Name,FullName,Description,Enabled,LastLogon,PasswordLastSet,PasswordRequired,PrincipalSource,@{Name='SID';Expression={$_.SID.Value}} }
Save-RawJson 'local-admins' { Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource,@{Name='SID';Expression={$_.SID.Value}} }
Save-RawJson 'processes' { Get-Process | Select-Object Id,ProcessName,Path,StartTime,Company,Description }
Save-RawJson 'services' { Get-CimInstance Win32_Service | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'scheduled-tasks' {
    Get-ScheduledTask | ForEach-Object {
        [pscustomobject]@{
            TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = [string]$_.State
            Author = $_.Author; Description = $_.Description
            UserId = $_.Principal.UserId; RunLevel = [string]$_.Principal.RunLevel
            Hidden = $_.Settings.Hidden
            Actions = ($_.Actions | ForEach-Object { Get-OpsForgeTaskActionText $_ }) -join '; '
            Triggers = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join '; '
        }
    }
}
Save-RawJson 'startup-programs' { Get-CimInstance Win32_StartupCommand | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'network-connections' { Get-NetTCPConnection | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'listening-ports' { Get-NetTCPConnection | Where-Object State -eq 'Listen' | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'firewall-profile' { Get-NetFirewallProfile | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'hotfixes' { Get-HotFix | Select-Object Source,Description,HotFixID,InstalledBy,InstalledOn,Caption,CSName,FixComments,Name,ServicePackInEffect,Status }
Save-RawJson 'recent-logons' {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 | ForEach-Object {
        [pscustomobject]@{
            TimeCreated = $_.TimeCreated; Id = $_.Id; RecordId = $_.RecordId
            ProviderName = $_.ProviderName; MachineName = $_.MachineName
            Message = $_.Message; UserId = $(if ($_.UserId) { $_.UserId.Value } else { $null })
            Xml = $_.ToXml()
        }
    }
}
Save-RawJson 'defender-status' { Get-MpComputerStatus | Select-Object -Property * -ExcludeProperty CimClass,CimInstanceProperties,CimSystemProperties }
Save-RawJson 'event-log-summary' {
    Get-EventLog -List | ForEach-Object {
        [pscustomobject]@{ Log = $_.Log; Entries = $_.Entries.Count; MaximumKilobytes = $_.MaximumKilobytes; OverflowAction = [string]$_.OverflowAction }
    }
}
Save-RawJson 'installed-software' {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
}

$historyPaths = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
) | Select-Object -Unique
$historyPaths | Where-Object { Test-Path $_ } | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\powershell-history-paths.txt')

$runningProcesses = Get-Process
$services = Get-CimInstance Win32_Service
$scheduledTasks = Get-ScheduledTask
$firewallProfiles = Get-NetFirewallProfile
$rdpListeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -eq 3389 -and $_.LocalAddress -in '0.0.0.0','::' }

$runningProcesses | ForEach-Object {
    $path = $null
    try { $path = $_.Path } catch { }
    if (Test-OpsForgeUserWritablePath $path) {
        $seed = Get-OpsForgeIdSeed "$($_.Id)-$path"
        $signed = $null
        try { $signed = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop } catch { }
        if (-not $signed -or $signed.Status -ne 'Valid') {
            $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-UNSIGNED-PROC-$seed" 'Unsigned process running from user-writable path' 'high' 'endpoint' "pid=$($_.Id) path=$path" 'Validate binary signature and isolate the host if unauthorized execution is confirmed.'))
        }
    }
}

$services | ForEach-Object {
    if ($_.PathName -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|powershell.*(-enc|-encodedcommand)') {
        $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-SERVICE-$(Get-OpsForgeIdSeed $_.Name)" 'Service binary path is suspicious' 'high' 'endpoint' "$($_.Name) $($_.PathName)" 'Validate service creation source and binary signature.'))
    }
}

$scheduledTasks | ForEach-Object {
    $action = ($_.Actions | ForEach-Object { Get-OpsForgeTaskActionText $_ }) -join '; '
    if ($action -match '(?i)powershell.*(-enc|-encodedcommand)|\\AppData\\|\\Temp\\|\\Users\\Public\\') {
        $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-TASK-$(Get-OpsForgeIdSeed ($_.TaskPath + $_.TaskName))" 'Suspicious scheduled task action' 'high' 'endpoint' "$($_.TaskPath)$($_.TaskName): $action" 'Export task XML and verify task author, action, and trigger.'))
    }
}

try {
    $defender = Get-MpComputerStatus
    if (-not $defender.RealTimeProtectionEnabled) {
        $findings.Add((New-OpsForgeFinding 'WIN-TRIAGE-DEFENDER-DISABLED' 'Defender real-time protection is disabled' 'critical' 'hardening' 'Get-MpComputerStatus RealTimeProtectionEnabled=False' 'Re-enable protection or confirm documented maintenance exception.'))
    }
} catch { }

$firewallProfiles | Where-Object { -not $_.Enabled } | ForEach-Object {
    $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-FW-$($_.Name)" 'Windows firewall profile is disabled' 'high' 'network' "$($_.Name) profile disabled" 'Re-enable firewall profile or document compensating controls.'))
}

$rdpListeners | ForEach-Object {
    $findings.Add((New-OpsForgeFinding 'WIN-TRIAGE-RDP-EXPOSED' 'RDP listens on all interfaces' 'high' 'network' "$($_.LocalAddress):$($_.LocalPort)" 'Restrict RDP exposure with firewall policy and validate remote access requirements.'))
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$processCount = [int](@($runningProcesses).Count)
$serviceCount = [int](@($services).Count)
$scheduledTaskCount = [int](@($scheduledTasks).Count)
$reportStats = @{
    Processes = $processCount
    Services = $serviceCount
    ScheduledTasks = $scheduledTaskCount
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Triage Collector' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @(
        'raw\processes.json',
        'raw\services.json',
        'raw\scheduled-tasks.json',
        'raw\network-connections.json',
        'raw\firewall-profiles.json'
    ) `
    -Limitations @(
        'Some process paths and signatures may be unavailable without admin rights.',
        'Event log and Defender data depend on local policy and installed components.'
    ) `
    -NextSteps @(
        'Review suspicious process, service, task, Defender, firewall, and RDP findings.',
        'Use the raw JSON files to confirm command lines, paths, and owners.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows triage collector' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
