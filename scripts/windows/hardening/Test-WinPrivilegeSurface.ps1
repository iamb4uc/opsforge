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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinPrivilegeSurface'
$findings = New-Object System.Collections.Generic.List[object]

$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
$rdp = Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue
$backup = Get-LocalGroupMember -Group 'Backup Operators' -ErrorAction SilentlyContinue
$services = Get-CimInstance Win32_Service
$tasks = Get-ScheduledTask

$admins | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\local-admins.json')
$rdp | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\rdp-users.json')
$backup | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\backup-operators.json')
$services | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\services.json')
$tasks | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\scheduled-tasks.json')

foreach ($member in @($admins)) {
    if ($member.ObjectClass -eq 'User' -and $member.Name -notmatch '\\Administrator$') {
        $findings.Add((New-OpsForgeFinding "WIN-PRIV-ADMIN-$(Get-OpsForgeIdSeed $member.Name)" 'Non-default local administrator present' 'medium' 'hardening' $member.Name 'Validate local administrator membership against access policy.'))
    }
}
if (@($rdp).Count -gt 0) {
    $rdpNames = (@($rdp) | ForEach-Object { $_.Name }) -join '; '
    $findings.Add((New-OpsForgeFinding 'WIN-PRIV-RDP-USERS' 'Remote Desktop Users group has members' 'medium' 'hardening' $rdpNames 'Validate interactive remote access membership.'))
}
if (@($backup).Count -gt 0) {
    $backupNames = (@($backup) | ForEach-Object { $_.Name }) -join '; '
    $findings.Add((New-OpsForgeFinding 'WIN-PRIV-BACKUP-USERS' 'Backup Operators group has members' 'high' 'hardening' $backupNames 'Review Backup Operators as sensitive privilege assignment.'))
}
foreach ($svc in $services | Where-Object { $_.StartName -eq 'LocalSystem' }) {
    if ($svc.PathName -match '(?i)\\Users\\|\\ProgramData\\|\\Temp\\') {
        $findings.Add((New-OpsForgeFinding "WIN-PRIV-SYSTEM-SVC-$(Get-OpsForgeIdSeed $svc.Name)" 'LocalSystem service references writable-looking path' 'high' 'hardening' "$($svc.Name): $($svc.PathName)" 'Harden ACLs and verify service binary ownership.'))
    }
}
foreach ($task in $tasks) {
    if ($task.Principal.UserId -match 'SYSTEM|Administrators') {
        $action = ($task.Actions | ForEach-Object { Get-OpsForgeTaskActionText $_ }) -join '; '
        if ($action -match '(?i)\\Users\\|\\AppData\\|\\Temp\\') {
            $findings.Add((New-OpsForgeFinding "WIN-PRIV-ADMIN-TASK-$(Get-OpsForgeIdSeed ($task.TaskPath + $task.TaskName))" 'Privileged scheduled task executes writable-looking path' 'high' 'hardening' "$($task.TaskPath)$($task.TaskName): $action" 'Validate task path and remove unauthorized privileged automation.'))
        }
    }
}

try {
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uac | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\uac.json')
    if ($uac.EnableLUA -eq 0) {
        $findings.Add((New-OpsForgeFinding 'WIN-PRIV-UAC-OFF' 'UAC is disabled' 'high' 'hardening' 'EnableLUA=0' 'Enable UAC unless there is a documented exception.'))
    }
} catch { }

Get-Service WinRM,TermService -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\remote-services.json')

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$adminCount = [int](@($admins).Count)
$serviceCount = [int](@($services).Count)
$scheduledTaskCount = [int](@($tasks).Count)
$reportStats = @{
    LocalAdministrators = $adminCount
    Services = $serviceCount
    ScheduledTasks = $scheduledTaskCount
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Local Privilege Surface Audit' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @(
        'raw\local-admins.json',
        'raw\rdp-users.json',
        'raw\backup-operators.json',
        'raw\services.json',
        'raw\scheduled-tasks.json',
        'raw\uac.json',
        'raw\remote-services.json'
    ) `
    -Limitations @(
        'Group membership visibility can differ on domain-joined or policy-managed hosts.',
        'Privilege risk depends on local ACLs and domain policy that this script does not change.'
    ) `
    -NextSteps @(
        'Review local admins, Backup Operators, RDP users, UAC state, and privileged task findings.',
        'Confirm privileged service and task paths before changing memberships or configs.'
    )
Copy-Item -Force -Path (Join-Path $OutDir 'report.md') -Destination (Join-Path $OutDir 'privilege-surface-report.md')
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows local privilege surface audit' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
