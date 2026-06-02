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
    $lines = @($Title, "Output: $OutputDirectory", "Findings: $FindingCount")
    Set-Content -Encoding UTF8 -Path (Join-Path $OutputDirectory 'summary.txt') -Value $lines
}

function Save-OpsForgeReport {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$Title,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [hashtable]$Stats = @{},
        [string[]]$EvidenceFiles = @(),
        [string[]]$Limitations = @(),
        [string[]]$NextSteps = @(),
        [string]$CollectionMode = 'read-only'
    )

    $findingList = @($Findings)
    $severityOrder = @('critical','high','medium','low','info')
    $severityRank = @{
        critical = 0
        high = 1
        medium = 2
        low = 3
        info = 4
    }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("# $Title")
    $lines.Add('')
    $lines.Add("- Host: $(Get-OpsForgeHostName)")
    $lines.Add("- Generated: $timestamp")
    $lines.Add("- Collection mode: $CollectionMode")
    $lines.Add("- Output: $OutputDirectory")
    $lines.Add('')
    $lines.Add('## Finding Count')
    $lines.Add('')
    $lines.Add("- Total: $($findingList.Count)")
    foreach ($severity in $severityOrder) {
        $count = @($findingList | Where-Object { $_.severity -eq $severity }).Count
        $lines.Add("- ${severity}: $count")
    }

    if ($Stats.Count -gt 0) {
        $lines.Add('')
        $lines.Add('## Collected')
        $lines.Add('')
        foreach ($key in ($Stats.Keys | Sort-Object)) {
            $lines.Add("- ${key}: $($Stats[$key])")
        }
    }

    $lines.Add('')
    $lines.Add('## Top Findings')
    $lines.Add('')
    $topFindings = $findingList |
        Sort-Object @{ Expression = { $severityRank[[string]$_.severity] } }, title |
        Select-Object -First 10
    if (@($topFindings).Count -eq 0) {
        $lines.Add('No findings recorded.')
    } else {
        foreach ($finding in $topFindings) {
            $severity = ([string]$finding.severity).ToUpperInvariant()
            $lines.Add("- [$severity] $($finding.title) - $($finding.evidence)")
        }
    }

    $lines.Add('')
    $lines.Add('## Evidence Files')
    $lines.Add('')
    if (@($EvidenceFiles).Count -eq 0) {
        $lines.Add('- raw\')
        $lines.Add('- findings.json')
        $lines.Add('- summary.txt')
    } else {
        foreach ($file in $EvidenceFiles) {
            $lines.Add("- $file")
        }
    }

    $lines.Add('')
    $lines.Add('## Collection Limitations')
    $lines.Add('')
    if (@($Limitations).Count -eq 0) {
        $lines.Add('No explicit limitations recorded. Some data can still be partial without admin rights.')
    } else {
        foreach ($limitation in $Limitations) {
            $lines.Add("- $limitation")
        }
    }

    $lines.Add('')
    $lines.Add('## Next Steps')
    $lines.Add('')
    if (@($NextSteps).Count -eq 0) {
        $lines.Add('- Review high and critical findings first.')
        $lines.Add('- Check raw evidence before making changes.')
        $lines.Add('- Treat missing data as partial collection, not proof of absence.')
    } else {
        foreach ($step in $NextSteps) {
            $lines.Add("- $step")
        }
    }

    Set-Content -Encoding UTF8 -Path (Join-Path $OutputDirectory 'report.md') -Value $lines
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

function Get-OpsForgeTaskActionText {
    param([object]$Action)
    if ($null -eq $Action) { return '' }

    $execute = ''
    $arguments = ''
    if ($Action.PSObject.Properties.Name -contains 'Execute') {
        $execute = [string]$Action.Execute
    }
    if ($Action.PSObject.Properties.Name -contains 'Arguments') {
        $arguments = [string]$Action.Arguments
    }
    if ($execute -or $arguments) {
        return "$execute $arguments".Trim()
    }

    return $Action.GetType().Name
}
