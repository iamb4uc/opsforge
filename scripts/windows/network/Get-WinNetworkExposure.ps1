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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Get-WinNetworkExposure'
$findings = New-Object System.Collections.Generic.List[object]

$processById = @{}
Get-Process | ForEach-Object { $processById[$_.Id] = $_ }
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$listeners = $connections | Where-Object { $_.State -eq 'Listen' }
$services = Get-CimInstance Win32_Service

$records = foreach ($conn in $listeners) {
    $proc = $processById[$conn.OwningProcess]
    $path = $null
    try { $path = $proc.Path } catch { }
    $svc = $services | Where-Object { $_.ProcessId -eq $conn.OwningProcess } | Select-Object -First 1
    [pscustomobject]@{
        LocalAddress = $conn.LocalAddress
        LocalPort = $conn.LocalPort
        OwningProcess = $conn.OwningProcess
        ProcessName = if ($proc) { $proc.ProcessName } else { $null }
        ProcessPath = $path
        ServiceName = if ($svc) { $svc.Name } else { $null }
        ServiceDisplayName = if ($svc) { $svc.DisplayName } else { $null }
    }
}

$records | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\listening-tcp.json')
$connections | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\tcp-connections.json')
Get-DnsClientCache -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\dns-cache.json')
Get-NetAdapter -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\net-adapters.json')
Get-NetRoute -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\routes.json')

foreach ($record in $records) {
    $seed = [Math]::Abs(("$($record.LocalAddress):$($record.LocalPort):$($record.OwningProcess)").GetHashCode())
    if ($record.LocalPort -in 22, 3389, 5985, 5986, 445, 135, 139 -and $record.LocalAddress -in '0.0.0.0','::') {
        $findings.Add((New-OpsForgeFinding "WIN-NET-ADMIN-$seed" 'Administrative service listens on all interfaces' 'high' 'network' "$($record.LocalAddress):$($record.LocalPort) $($record.ProcessName)" 'Confirm exposure is intended and restricted by firewall policy.'))
    }
    if (Test-OpsForgeUserWritablePath $record.ProcessPath) {
        $findings.Add((New-OpsForgeFinding "WIN-NET-USERPATH-$seed" 'Listening process runs from user-writable path' 'high' 'network' "$($record.LocalAddress):$($record.LocalPort) $($record.ProcessPath)" 'Validate binary signature and ownership, then isolate if unauthorized.'))
    }
    if (-not $record.ProcessPath -and $record.ProcessName -notin 'System','Idle') {
        $findings.Add((New-OpsForgeFinding "WIN-NET-UNKNOWN-$seed" 'Listening socket has unknown process path' 'medium' 'network' "$($record.LocalAddress):$($record.LocalPort) pid=$($record.OwningProcess)" 'Inspect the owning process with elevated privileges.'))
    }
}

Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
Save-OpsForgeReport `
    -OutputDirectory $OutDir `
    -Title 'Windows Network Exposure Mapper' `
    -Findings $findings.ToArray() `
    -Stats @{
        ListeningSockets = @($records).Count
        TcpConnections = @($connections).Count
    } `
    -EvidenceFiles @(
        'raw\listening-tcp.json',
        'raw\tcp-connections.json',
        'raw\dns-cache.json',
        'raw\net-adapters.json',
        'raw\routes.json'
    ) `
    -Limitations @(
        'Process paths can be missing for protected processes without enough privilege.',
        'Firewall rule mapping is handled by the firewall auditor, not this mapper.'
    ) `
    -NextSteps @(
        'Review admin ports listening on all interfaces.',
        'Check unknown process paths and user-writable listener binaries.'
    )
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows network exposure mapper' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
