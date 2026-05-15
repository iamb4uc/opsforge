#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-OpsForgeHostName {
    return $env:COMPUTERNAME
}

function New-OpsForgeOutputDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$ScriptName
    )
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hostName = (Get-OpsForgeHostName) -replace '[\\/:*?"<>| ]', '_'
    $dir = Join-Path $OutputPath "$hostName-$ScriptName-$timestamp"
    $candidate = $dir
    $counter = 1
    while (Test-Path $candidate) {
        $counter++
        $candidate = "$dir-$counter"
    }
    $dir = $candidate
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'raw') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'normalized') | Out-Null
    return (Resolve-Path $dir).Path
}

function New-OpsForgeFinding {
    param(
        [string]$Id,
        [string]$Title,
        [ValidateSet('critical','high','medium','low','info')][string]$Severity,
        [string]$Category,
        [string]$Evidence,
        [string]$Recommendation
    )
    [pscustomobject]@{
        id = $Id
        title = $Title
        severity = $Severity
        host = Get-OpsForgeHostName
        category = $Category
        evidence = $Evidence
        recommendation = $Recommendation
    }
}

function Save-OpsForgeFindings {
    param(
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )
    $jsonPath = Join-Path $OutputDirectory 'findings.json'
    $normalizedPath = Join-Path $OutputDirectory 'normalized\findings.json'
    if (@($Findings).Count -eq 0) {
        '[]' | Set-Content -Encoding UTF8 -Path $jsonPath
    } else {
        @($Findings) | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $jsonPath
    }
    Copy-Item -Force -Path $jsonPath -Destination $normalizedPath
}

function Save-OpsForgeSummary {
    param(
        [string]$OutputDirectory,
        [string]$Title,
        [int]$FindingCount
    )
    @(
        $Title
        "Output: $OutputDirectory"
        "Findings: $FindingCount"
    ) | Set-Content -Encoding UTF8 -Path (Join-Path $OutputDirectory 'summary.txt')
}

function Test-OpsForgeUserWritablePath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return $Path -match '\\Users\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\ProgramData\\'
}

function Get-OpsForgeSafeFileName {
    param([string]$Name)
    return ($Name -replace '[\\/:*?"<>| ]', '_')
}
