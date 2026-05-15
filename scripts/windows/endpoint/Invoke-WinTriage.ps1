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
        & $Collector | ConvertTo-Json -Depth 7 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir "raw\$Name.json")
    } catch {
        "Collector $Name failed: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir "raw\$Name.error.txt")
    }
}

Save-RawJson 'os-version' { Get-CimInstance Win32_OperatingSystem }
Save-RawJson 'local-users' { Get-LocalUser }
Save-RawJson 'local-admins' { Get-LocalGroupMember -Group 'Administrators' }
Save-RawJson 'processes' { Get-Process | Select-Object Id,ProcessName,Path,StartTime,Company,Description }
Save-RawJson 'services' { Get-CimInstance Win32_Service }
Save-RawJson 'scheduled-tasks' { Get-ScheduledTask }
Save-RawJson 'startup-programs' { Get-CimInstance Win32_StartupCommand }
Save-RawJson 'network-connections' { Get-NetTCPConnection }
Save-RawJson 'listening-ports' { Get-NetTCPConnection | Where-Object State -eq 'Listen' }
Save-RawJson 'firewall-profile' { Get-NetFirewallProfile }
Save-RawJson 'hotfixes' { Get-HotFix }
Save-RawJson 'recent-logons' { Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 100 }
Save-RawJson 'defender-status' { Get-MpComputerStatus }
Save-RawJson 'event-log-summary' { Get-EventLog -List | Select-Object Log,Entries,MaximumKilobytes,OverflowAction }
Save-RawJson 'installed-software' {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
}

$historyPaths = @(
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
) | Select-Object -Unique
$historyPaths | Where-Object { Test-Path $_ } | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\powershell-history-paths.txt')

Get-Process | ForEach-Object {
    $path = $null
    try { $path = $_.Path } catch { }
    if (Test-OpsForgeUserWritablePath $path) {
        $seed = [Math]::Abs(("$($_.Id)-$path").GetHashCode())
        $signed = $null
        try { $signed = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop } catch { }
        if (-not $signed -or $signed.Status -ne 'Valid') {
            $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-UNSIGNED-PROC-$seed" 'Unsigned process running from user-writable path' 'high' 'endpoint' "pid=$($_.Id) path=$path" 'Validate binary signature and isolate the host if unauthorized execution is confirmed.'))
        }
    }
}

Get-CimInstance Win32_Service | ForEach-Object {
    if ($_.PathName -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|powershell.*(-enc|-encodedcommand)') {
        $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-SERVICE-$([Math]::Abs($_.Name.GetHashCode()))" 'Service binary path is suspicious' 'high' 'endpoint' "$($_.Name) $($_.PathName)" 'Validate service creation source and binary signature.'))
    }
}

Get-ScheduledTask | ForEach-Object {
    $action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
    if ($action -match '(?i)powershell.*(-enc|-encodedcommand)|\\AppData\\|\\Temp\\|\\Users\\Public\\') {
        $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-TASK-$([Math]::Abs(($_.TaskPath + $_.TaskName).GetHashCode()))" 'Suspicious scheduled task action' 'high' 'endpoint' "$($_.TaskPath)$($_.TaskName): $action" 'Export task XML and verify task author, action, and trigger.'))
    }
}

try {
    $defender = Get-MpComputerStatus
    if (-not $defender.RealTimeProtectionEnabled) {
        $findings.Add((New-OpsForgeFinding 'WIN-TRIAGE-DEFENDER-DISABLED' 'Defender real-time protection is disabled' 'critical' 'hardening' 'Get-MpComputerStatus RealTimeProtectionEnabled=False' 'Re-enable protection or confirm documented maintenance exception.'))
    }
} catch { }

Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object {
    $findings.Add((New-OpsForgeFinding "WIN-TRIAGE-FW-$($_.Name)" 'Windows firewall profile is disabled' 'high' 'network' "$($_.Name) profile disabled" 'Re-enable firewall profile or document compensating controls.'))
}

Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 3389 -and $_.LocalAddress -in '0.0.0.0','::' } | ForEach-Object {
    $findings.Add((New-OpsForgeFinding 'WIN-TRIAGE-RDP-EXPOSED' 'RDP listens on all interfaces' 'high' 'network' "$($_.LocalAddress):$($_.LocalPort)" 'Restrict RDP exposure with firewall policy and validate remote access requirements.'))
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$reportLines = @('# Windows Triage Collector', '', "- Host: $env:COMPUTERNAME", "- Findings: $($findings.Count)", '', 'Raw evidence is stored under `raw\`.')
Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'report.md') -Value $reportLines
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows triage collector' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
