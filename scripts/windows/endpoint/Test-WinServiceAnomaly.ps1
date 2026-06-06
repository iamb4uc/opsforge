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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinServiceAnomaly'
$findings = New-Object System.Collections.Generic.List[object]
$services = Get-CimInstance Win32_Service
$services | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\services.json')

foreach ($svc in $services) {
    $path = [string]$svc.PathName
    $seed = [Math]::Abs(($svc.Name + $path).GetHashCode())
    if ($path -match '^[A-Za-z]:\\[^"].*\s+.*\.exe') {
        $findings.Add((New-OpsForgeFinding "WIN-SVC-UNQUOTED-$seed" 'Service has unquoted executable path with spaces' 'medium' 'endpoint' "$($svc.Name): $path" 'Quote the service ImagePath and validate directory ACLs.'))
    }
    if ($path -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\') {
        $findings.Add((New-OpsForgeFinding "WIN-SVC-USERPATH-$seed" 'Service binary runs from user-writable path' 'high' 'endpoint' "$($svc.Name): $path" 'Validate binary signature, service owner, and creation time.'))
    }
    if ($path -match '(?i)powershell.*(-enc|-encodedcommand)|cmd\.exe\s+/c|rundll32.*\\Users\\|mshta|wscript|cscript') {
        $findings.Add((New-OpsForgeFinding "WIN-SVC-SUSPARGS-$seed" 'Service uses suspicious command arguments' 'high' 'endpoint' "$($svc.Name): $path" 'Inspect command line and disable unauthorized service persistence.'))
    }
    if ($svc.StartName -eq 'LocalSystem' -and $path -match '(?i)\\ProgramData\\|\\Users\\') {
        $findings.Add((New-OpsForgeFinding "WIN-SVC-SYSTEM-USERPATH-$seed" 'LocalSystem service points to writable-looking path' 'high' 'endpoint' "$($svc.Name): $path" 'Harden ACLs and verify service binary provenance.'))
    }
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
$serviceCount = [int](@($services).Count)
$reportStats = @{
    Services = $serviceCount
}
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Service Anomaly Auditor' `
    -Findings $findings.ToArray() `
    -Stats $reportStats `
    -EvidenceFiles @('raw\services.json') `
    -Limitations @(
        'Service creation time and file ACL review are not always available from Win32_Service alone.'
    ) `
    -NextSteps @(
        'Review high severity service paths first.',
        'Check binary signatures and directory permissions for flagged services.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows service anomaly auditor' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
