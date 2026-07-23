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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinDefenderStatus'
$findings = New-Object System.Collections.Generic.List[object]

try {
    $status = Get-MpComputerStatus
    $prefs = Get-MpPreference
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
    $status | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\defender-status.json')
    $prefs | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\defender-preferences.json')
    $threats | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\threat-history.json')
    if (-not $status.RealTimeProtectionEnabled) {
        $findings.Add((New-OpsForgeFinding 'WIN-DEFENDER-REALTIME-OFF' 'Defender real-time protection is disabled' 'critical' 'hardening' 'RealTimeProtectionEnabled=False' 'Re-enable real-time protection or document a short maintenance exception.'))
    }
    if (-not $status.AntispywareEnabled -or -not $status.AntivirusEnabled) {
        $findings.Add((New-OpsForgeFinding 'WIN-DEFENDER-AV-OFF' 'Defender antivirus or antispyware is disabled' 'critical' 'hardening' 'Antivirus/Antispyware disabled' 'Re-enable Defender components and investigate tampering.'))
    }
    if ($status.AntivirusSignatureAge -gt 3) {
        $findings.Add((New-OpsForgeFinding 'WIN-DEFENDER-SIG-OLD' 'Defender signatures are stale' 'high' 'hardening' "Signature age: $($status.AntivirusSignatureAge) days" 'Update signatures and verify update channel health.'))
    }
    foreach ($exclusion in @($prefs.ExclusionPath) + @($prefs.ExclusionProcess) + @($prefs.ExclusionExtension)) {
        if ($exclusion -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\') {
            $findings.Add((New-OpsForgeFinding "WIN-DEFENDER-EXCLUSION-$(Get-OpsForgeIdSeed $exclusion)" 'Suspicious Defender exclusion' 'high' 'hardening' $exclusion 'Remove broad or user-writable exclusions unless formally approved.'))
        }
    }
} catch {
    "Unable to query Defender: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\defender-error.txt')
    $findings.Add((New-OpsForgeFinding 'WIN-DEFENDER-QUERY-FAILED' 'Unable to query Defender status' 'medium' 'hardening' $_.Exception.Message 'Run with administrative privileges and confirm Defender is installed.'))
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Defender Status Auditor' `
    -Findings $findings.ToArray() `
    -EvidenceFiles @(
        'raw\defender-status.json',
        'raw\defender-preferences.json',
        'raw\threat-history.json',
        'raw\defender-error.txt'
    ) `
    -Limitations @(
        'Defender cmdlets may be unavailable when Defender is removed or managed differently.',
        'Some settings require admin rights or current Defender platform support.'
    ) `
    -NextSteps @(
        'Review disabled protection, stale signatures, and user-writable exclusions first.',
        'Confirm whether any exclusion is expected before removing it.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows Defender status auditor' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
