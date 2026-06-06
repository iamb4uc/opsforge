#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) 'output'),
    [int]$MaxEvents = 2000,
    [switch]$Json,
    [switch]$Markdown,
    [switch]$Quiet
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
. (Join-Path $RepoRoot 'lib\windows\Common.ps1')
. (Join-Path $RepoRoot 'lib\windows\Logging.ps1')

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'New-WinEventTimeline'
$findings = New-Object System.Collections.Generic.List[object]
$logs = @('Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-Sysmon/Operational')
$important = @(4624,4625,4672,4688,4720,4728,4732,7045,4698,1102,4104)
$timeline = New-Object System.Collections.Generic.List[object]

foreach ($log in $logs) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $important } -MaxEvents $MaxEvents -ErrorAction Stop
        foreach ($event in $events) {
            $severity = 'info'
            if ($event.Id -in 1102,4720,4728,4732,7045,4698) { $severity = 'high' }
            elseif ($event.Id -in 4625,4672,4104) { $severity = 'medium' }
            $summary = ($event.Message -replace '\s+', ' ')
            if ($summary.Length -gt 300) { $summary = $summary.Substring(0,300) }
            $timeline.Add([pscustomobject]@{
                timestamp = $event.TimeCreated
                source = $log
                event_type = $event.Id
                user = $event.UserId
                process = $event.ProviderName
                summary = $summary
                severity = $severity
            })
            if ($event.Id -in 1102,4720,4728,4732,7045,4698) {
                $seed = [Math]::Abs(("$log-$($event.RecordId)-$($event.Id)").GetHashCode())
                $findings.Add((New-OpsForgeFinding "WIN-EVENT-$seed" "Important security event $($event.Id)" $severity 'forensic' "$log record=$($event.RecordId) time=$($event.TimeCreated)" 'Review the event details and correlate with change tickets and endpoint activity.'))
            }
        }
    } catch {
        "Unable to read ${log}: $($_.Exception.Message)" | Add-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\event-read-errors.txt')
    }
}

$ordered = $timeline.ToArray() | Sort-Object timestamp
$ordered | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'timeline.csv')
$ordered | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\timeline.json')
@('# Windows Event Timeline','','| timestamp | source | event_type | severity | summary |','|---|---|---:|---|---|') + (
    $ordered | Select-Object -First 500 | ForEach-Object { "| $($_.timestamp) | $($_.source) | $($_.event_type) | $($_.severity) | $($_.summary -replace '\|','/') |" }
) | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'timeline.md')
Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$timelineEventCount = [int](@($ordered).Count)
$logCount = [int](@($logs).Count)
$reportStats = @{
    TimelineEvents = $timelineEventCount
    LogsRequested = $logCount
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Event Timeline Builder' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @(
        'timeline.csv',
        'timeline.md',
        'raw\timeline.json',
        'raw\event-read-errors.txt'
    ) `
    -Limitations @(
        'Some event logs may be missing, disabled, or unreadable without enough privilege.',
        'Process creation and script block events depend on audit policy being enabled.'
    ) `
    -NextSteps @(
        'Review high severity account, service install, task creation, and log-clear events.',
        'Use timeline.csv for sorting and timeline.md for quick reading.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows event timeline builder' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
