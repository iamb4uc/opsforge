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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinScheduledTasks'
$findings = New-Object System.Collections.Generic.List[object]
$rawPath = Join-Path $OutDir 'raw\scheduled-tasks.json'

function Get-TaskTriggerName {
    param([object]$Trigger)
    if ($null -eq $Trigger) { return '' }
    if ($Trigger.PSObject.Properties.Name -contains 'CimClass' -and $null -ne $Trigger.CimClass) {
        return [string]$Trigger.CimClass.CimClassName
    }
    if ($Trigger.PSObject.Properties.Name -contains 'TriggerType') {
        return [string]$Trigger.TriggerType
    }
    return $Trigger.GetType().Name
}

$tasks = Get-ScheduledTask | ForEach-Object {
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop } catch { }
    [pscustomobject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        Author = $_.Author
        UserId = $_.Principal.UserId
        RunLevel = $_.Principal.RunLevel
        Hidden = $_.Settings.Hidden
        Actions = ($_.Actions | ForEach-Object { Get-OpsForgeTaskActionText $_ }) -join '; '
        Triggers = ($_.Triggers | ForEach-Object { Get-TaskTriggerName $_ }) -join '; '
        LastRunTime = if ($info) { $info.LastRunTime } else { $null }
        NextRunTime = if ($info) { $info.NextRunTime } else { $null }
    }
}

$tasks | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $rawPath

foreach ($task in $tasks) {
    $action = [string]$task.Actions
    $idSeed = [Math]::Abs(($task.TaskPath + $task.TaskName + $action).GetHashCode())
    if ($action -match '(?i)powershell.*(-enc|-encodedcommand)') {
        $findings.Add((New-OpsForgeFinding "WIN-TASK-ENC-$idSeed" 'Scheduled task runs encoded PowerShell' 'high' 'persistence' "$($task.TaskPath)$($task.TaskName): $action" 'Inspect the task XML, validate owner, and disable unauthorized tasks.'))
    }
    if ($action -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\') {
        $findings.Add((New-OpsForgeFinding "WIN-TASK-USERPATH-$idSeed" 'Scheduled task executes from user-writable path' 'high' 'persistence' "$($task.TaskPath)$($task.TaskName): $action" 'Validate the executable path and remove unauthorized persistence.'))
    }
    if ($task.Hidden) {
        $findings.Add((New-OpsForgeFinding "WIN-TASK-HIDDEN-$idSeed" 'Hidden scheduled task' 'medium' 'persistence' "$($task.TaskPath)$($task.TaskName)" 'Confirm the hidden task is approved and expected.'))
    }
    if ([string]$task.UserId -match 'SYSTEM') {
        $findings.Add((New-OpsForgeFinding "WIN-TASK-SYSTEM-$idSeed" 'Scheduled task runs as SYSTEM' 'low' 'persistence' "$($task.TaskPath)$($task.TaskName): $action" 'Review SYSTEM tasks with unusual actions or untrusted authors.'))
    }
    if ($task.Triggers -match 'Logon') {
        $findings.Add((New-OpsForgeFinding "WIN-TASK-LOGON-$idSeed" 'Scheduled task triggers at logon' 'low' 'persistence' "$($task.TaskPath)$($task.TaskName)" 'Validate logon-triggered persistence against approved software inventory.'))
    }
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$scheduledTaskCount = [int](@($tasks).Count)
$reportStats = @{
    ScheduledTasks = $scheduledTaskCount
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Scheduled Task Auditor' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @('raw\scheduled-tasks.json') `
    -Limitations @(
        'Some task metadata may be missing when task info cannot be read.',
        'Task creation time is not exposed cleanly by every scheduled task API.'
    ) `
    -NextSteps @(
        'Review encoded PowerShell, user-writable paths, hidden tasks, and logon triggers.',
        'Export suspicious task XML before disabling anything.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows scheduled task auditor' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
