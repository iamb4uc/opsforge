#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) 'output'),
    [int]$LookbackDays = 14,
    [switch]$Json,
    [switch]$Markdown,
    [switch]$Quiet
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
. (Join-Path $RepoRoot 'lib\windows\Common.ps1')
. (Join-Path $RepoRoot 'lib\windows\Logging.ps1')

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinLogTampering'
$findings = New-Object System.Collections.Generic.List[object]
$start = (Get-Date).AddDays(-1 * $LookbackDays)

function Add-EventFinding {
    param([string]$IdPrefix, [string]$Title, [string]$Severity, [object]$Event)
    $seed = [Math]::Abs(("$IdPrefix-$($Event.RecordId)-$($Event.TimeCreated)").GetHashCode())
    $findings.Add((New-OpsForgeFinding "$IdPrefix-$seed" $Title $Severity 'forensic' "$($Event.LogName) id=$($Event.Id) time=$($Event.TimeCreated) record=$($Event.RecordId)" 'Correlate with administrative activity, EDR telemetry, and change tickets.'))
}

function Save-LogTamperingFallbackReport {
    param([string]$Message)

    [string[]]$lines = @(
        '# Windows Log Tampering Detector',
        '',
        "- Host: $env:COMPUTERNAME",
        "- Findings: $([int]$findings.Count)",
        "- Events collected: $([int]$events.Count)",
        "- Lookback days: $LookbackDays",
        '',
        '## Evidence Files',
        '',
        '- raw\tampering-events.json',
        '- raw\audit-policy.txt',
        '- raw\audit-policy-error.txt',
        '- raw\security-services.json',
        '- findings.json',
        '',
        '## Collection Limitations',
        '',
        "- $Message",
        '- Large event gaps need deeper review than this first-pass check.',
        '- Audit policy and event log access can be restricted by local privilege.',
        '',
        '## Next Steps',
        '',
        '- Review log clear, audit policy, Defender config, and service stop findings.',
        '- Correlate timestamps with admin activity and endpoint telemetry.'
    )
    Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir 'report.md') -Value $lines
}

$events = New-Object System.Collections.Generic.List[object]
foreach ($query in @(
    @{ LogName='Security'; Id=1102 },
    @{ LogName='System'; Id=104 },
    @{ LogName='System'; Id=7036 },
    @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 },
    @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5007 }
)) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName=$query.LogName; Id=$query.Id; StartTime=$start } -ErrorAction Stop | ForEach-Object { $events.Add($_) }
    } catch { }
}
$events.ToArray() | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\tampering-events.json')

foreach ($event in $events) {
    switch ($event.Id) {
        1102 { Add-EventFinding 'WIN-LOG-CLEARED' 'Security event log was cleared' 'critical' $event }
        104 { Add-EventFinding 'WIN-LOG-CLEARED' 'Event log was cleared' 'high' $event }
        5007 { Add-EventFinding 'WIN-DEFENDER-CONFIG-CHANGED' 'Defender configuration changed' 'medium' $event }
        7036 {
            if ($event.Message -match '(?i)Windows Event Log.*stopped|Sysmon.*stopped|WinDefend.*stopped') {
                Add-EventFinding 'WIN-LOG-SERVICE-STOPPED' 'Security logging or protection service stopped' 'high' $event
            }
        }
    }
}

try {
    auditpol /get /category:* | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\audit-policy.txt')
    if (Select-String -Path (Join-Path $OutDir 'raw\audit-policy.txt') -Pattern 'No Auditing' -Quiet) {
        $findings.Add((New-OpsForgeFinding 'WIN-AUDIT-POLICY-WEAK' 'Audit policy contains disabled categories' 'medium' 'forensic' 'raw\audit-policy.txt' 'Review audit policy changes and restore required logging baselines.'))
    }
} catch {
    "Unable to query audit policy: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\audit-policy-error.txt')
}

try {
    Get-Service EventLog,Sysmon64,Sysmon,WinDefend -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\security-services.json')
} catch { }

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
try {
    Save-OpsForgeReport `
        -OutputDirectory $OutDir `
        -Title 'Windows Log Tampering Detector' `
        -Findings $findings.ToArray() `
        -Stats @{
            LookbackDays = $LookbackDays
            EventsCollected = @($events).Count
        } `
        -EvidenceFiles @(
            'raw\tampering-events.json',
            'raw\audit-policy.txt',
            'raw\audit-policy-error.txt',
            'raw\security-services.json'
        ) `
        -Limitations @(
            'Large event gaps need deeper review than this first-pass check.',
            'Audit policy and event log access can be restricted by local privilege.'
        ) `
        -NextSteps @(
            'Review log clear, audit policy, Defender config, and service stop findings.',
            'Correlate timestamps with admin activity and endpoint telemetry.'
        )
} catch {
    $message = "Unable to write full report: $($_.Exception.Message)"
    [string[]]$details = @(
        $message,
        "Script stack: $($_.ScriptStackTrace)"
    )
    Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir 'raw\report-write-error.txt') -Value $details
    Save-LogTamperingFallbackReport -Message $message
}

try {
    Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows log tampering detector' -FindingCount $findings.Count
} catch {
    [string[]]$summary = @(
        'Windows log tampering detector',
        "Output: $OutDir",
        "Findings: $([int]$findings.Count)",
        "Summary writer failed: $($_.Exception.Message)"
    )
    Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutDir 'summary.txt') -Value $summary
}
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
