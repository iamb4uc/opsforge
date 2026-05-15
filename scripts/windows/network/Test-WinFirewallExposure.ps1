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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Test-WinFirewallExposure'
$findings = New-Object System.Collections.Generic.List[object]
$profiles = Get-NetFirewallProfile
$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue
$filters = foreach ($rule in $rules) {
    $ports = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name = $rule.Name
        DisplayName = $rule.DisplayName
        Profile = $rule.Profile
        Protocol = (@($ports) | ForEach-Object { $_.Protocol }) -join ','
        LocalPort = (@($ports) | ForEach-Object { $_.LocalPort }) -join ','
        RemoteAddress = (@($addr) | ForEach-Object { $_.RemoteAddress }) -join ','
    }
}

$profiles | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\firewall-profiles.json')
$filters | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\inbound-allow-rules.json')

foreach ($profile in $profiles) {
    if (-not $profile.Enabled) {
        $findings.Add((New-OpsForgeFinding "WIN-FW-PROFILE-$($profile.Name)" 'Firewall profile is disabled' 'high' 'network' "$($profile.Name) disabled" 'Enable the firewall profile or document compensating controls.'))
    }
}
foreach ($rule in $filters) {
    $seed = [Math]::Abs(($rule.Name + $rule.LocalPort + $rule.RemoteAddress).GetHashCode())
    if ($rule.RemoteAddress -match 'Any|0\.0\.0\.0/0|\*' -and $rule.LocalPort -match '3389|445|5985|5986|22') {
        $findings.Add((New-OpsForgeFinding "WIN-FW-ADMIN-$seed" 'Administrative port allowed from broad source' 'high' 'network' "$($rule.DisplayName) port=$($rule.LocalPort) remote=$($rule.RemoteAddress)" 'Restrict administrative services to trusted source ranges.'))
    }
    if ($rule.LocalPort -match '^Any$|\*' -and $rule.RemoteAddress -match 'Any|0\.0\.0\.0/0|\*') {
        $findings.Add((New-OpsForgeFinding "WIN-FW-ANYANY-$seed" 'Inbound Any/Any allow rule enabled' 'critical' 'network' "$($rule.DisplayName)" 'Disable broad inbound allow rules unless formally approved.'))
    }
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
Copy-Item -Force -Path (Join-Path $OutDir 'findings.json') -Destination (Join-Path $OutDir 'firewall-findings.json')
@('# Windows Firewall Exposure Auditor','',"Findings: $($findings.Count)",'Raw firewall data is in `raw\`.') | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'firewall-report.md')
Copy-Item -Force -Path (Join-Path $OutDir 'firewall-report.md') -Destination (Join-Path $OutDir 'report.md')
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows firewall exposure auditor' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
