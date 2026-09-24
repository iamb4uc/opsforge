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
$collection = New-Object System.Collections.Generic.List[object]
$start = (Get-Date).AddDays(-1 * $LookbackDays)

function Add-CollectionStatus {
    param([string]$Name, [string]$Status, [string]$Detail)
    $collection.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
}

function Get-CollectionFailureStatus {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($ErrorRecord.Exception -is [System.UnauthorizedAccessException] -or $ErrorRecord.Exception.Message -match '(?i)access.*denied|not authorized') {
        return 'denied'
    }
    if ($ErrorRecord.CategoryInfo.Category -eq 'ObjectNotFound' -or $ErrorRecord.Exception.Message -match '(?i)not recognized|cannot find') {
        return 'unavailable'
    }
    return 'failed'
}

function Add-EventFinding {
    param([string]$IdPrefix, [string]$Title, [string]$Severity, [object]$Event)
    $seed = Get-OpsForgeIdSeed "$IdPrefix-$($Event.RecordId)-$($Event.TimeCreated)"
    $findings.Add((New-OpsForgeFinding "$IdPrefix-$seed" $Title $Severity 'forensic' "$($Event.LogName) id=$($Event.Id) time=$($Event.TimeCreated) record=$($Event.RecordId)" 'Correlate with administrative activity, EDR telemetry, and change tickets.'))
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
        Add-CollectionStatus -Name "event:$($query.LogName):$($query.Id)" -Status 'collected' -Detail ''
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Add-CollectionStatus -Name "event:$($query.LogName):$($query.Id)" -Status 'collected' -Detail 'no matching events'
        } else {
            Add-CollectionStatus -Name "event:$($query.LogName):$($query.Id)" -Status (Get-CollectionFailureStatus $_) -Detail $_.Exception.Message
        }
    }
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
    $auditOutput = & auditpol /get /category:* 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol exited with code ${LASTEXITCODE}: $auditOutput" }
    $auditOutput | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\audit-policy.txt')
    Add-CollectionStatus -Name 'auditpol' -Status 'collected' -Detail ''
    if (Select-String -Path (Join-Path $OutDir 'raw\audit-policy.txt') -Pattern 'No Auditing' -Quiet) {
        $findings.Add((New-OpsForgeFinding 'WIN-AUDIT-POLICY-WEAK' 'Audit policy contains disabled categories' 'medium' 'forensic' 'raw\audit-policy.txt' 'Review audit policy changes and restore required logging baselines.'))
    }
} catch {
    "Unable to query audit policy: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\audit-policy-error.txt')
    Add-CollectionStatus -Name 'auditpol' -Status (Get-CollectionFailureStatus $_) -Detail $_.Exception.Message
}

$services = New-Object System.Collections.Generic.List[object]
foreach ($serviceName in @('EventLog','Sysmon64','Sysmon','WinDefend')) {
    try {
        $services.Add((Get-Service -Name $serviceName -ErrorAction Stop))
        Add-CollectionStatus -Name "service:$serviceName" -Status 'collected' -Detail ''
    } catch {
        Add-CollectionStatus -Name "service:$serviceName" -Status (Get-CollectionFailureStatus $_) -Detail $_.Exception.Message
    }
}
$services.ToArray() | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\security-services.json')

$statusPath = Join-Path $OutDir 'normalized\collection-status.tsv'
@("source`tstatus`tdetail") + @($collection | ForEach-Object { "$(($_.Name) -replace "`t", ' ')`t$($_.Status)`t$(($_.Detail) -replace "`t|`r|`n", ' ')" }) |
    Set-Content -Encoding UTF8 -Path $statusPath

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$eventCount = [int]$events.Count
$reportStats = @{
    LookbackDays = [int]$LookbackDays
    EventsCollected = $eventCount
    CollectionStates = (@($collection | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Log Tampering Detector' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @(
        'raw\tampering-events.json',
        'raw\audit-policy.txt',
        'raw\audit-policy-error.txt',
        'raw\security-services.json',
        'normalized\collection-status.tsv'
    ) `
    -Limitations @(
        'Large event gaps need deeper review than this first-pass check.',
        'Audit policy and event log access can be restricted by local privilege.',
        'Collection status records collected, denied, and failed evidence separately.'
    ) `
    -NextSteps @(
        'Review log clear, audit policy, Defender config, and service stop findings.',
        'Correlate timestamps with admin activity and endpoint telemetry.'
    )

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
