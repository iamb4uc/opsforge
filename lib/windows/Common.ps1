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
    [string[]]$lines = @(
        [string]$Title,
        "Output: $OutputDirectory",
        "Findings: $FindingCount"
    )
    Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory 'summary.txt') -Value $lines
}

function Save-OpsForgeReport {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$Title,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [object]$Stats = $null,
        [object[]]$EvidenceFiles = @(),
        [object[]]$Limitations = @(),
        [object[]]$NextSteps = @(),
        [string]$CollectionMode = 'read-only'
    )

    $findingList = @($Findings)
    $statMap = @{}
    if ($Stats -is [hashtable]) {
        $statMap = $Stats
    }
    $severityOrder = @('critical','high','medium','low','info')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $lines = @()

    $lines += "# $Title"
    $lines += ''
    $lines += "- Host: $(Get-OpsForgeHostName)"
    $lines += "- Generated: $timestamp"
    $lines += "- Collection mode: $CollectionMode"
    $lines += "- Output: $OutputDirectory"
    $lines += ''
    $lines += '## Finding Count'
    $lines += ''
    $lines += "- Total: $($findingList.Count)"
    foreach ($severity in $severityOrder) {
        $count = 0
        foreach ($finding in $findingList) {
            $findingSeverity = Get-OpsForgeObjectField -InputObject $finding -Name 'severity'
            if ($findingSeverity -eq $severity) {
                $count++
            }
        }
        $lines += "- ${severity}: $count"
    }

    if ($statMap.Count -gt 0) {
        $lines += ''
        $lines += '## Collected'
        $lines += ''
        foreach ($key in ($statMap.Keys | Sort-Object)) {
            $lines += "- ${key}: $(ConvertTo-OpsForgeText $statMap[$key])"
        }
    }

    $lines += ''
    $lines += '## Top Findings'
    $lines += ''
    $topFindingLines = @()
    foreach ($severity in $severityOrder) {
        foreach ($finding in $findingList) {
            if ($topFindingLines.Count -ge 10) {
                break
            }
            $findingSeverity = Get-OpsForgeObjectField -InputObject $finding -Name 'severity'
            if ($findingSeverity -ne $severity) {
                continue
            }
            $title = Get-OpsForgeObjectField -InputObject $finding -Name 'title'
            $evidence = Get-OpsForgeObjectField -InputObject $finding -Name 'evidence'
            $topFindingLines += "- [$($severity.ToUpperInvariant())] $title - $evidence"
        }
    }
    if ($topFindingLines.Count -eq 0) {
        $lines += 'No findings recorded.'
    } else {
        foreach ($findingLine in $topFindingLines) {
            $lines += $findingLine
        }
    }

    $lines += ''
    $lines += '## Evidence Files'
    $lines += ''
    if (@($EvidenceFiles).Count -eq 0) {
        $lines += '- raw\'
        $lines += '- findings.json'
        $lines += '- summary.txt'
    } else {
        foreach ($file in $EvidenceFiles) {
            $lines += "- $(ConvertTo-OpsForgeText $file)"
        }
    }

    $lines += ''
    $lines += '## Collection Limitations'
    $lines += ''
    if (@($Limitations).Count -eq 0) {
        $lines += 'No explicit limitations recorded. Some data can still be partial without admin rights.'
    } else {
        foreach ($limitation in $Limitations) {
            $lines += "- $(ConvertTo-OpsForgeText $limitation)"
        }
    }

    $lines += ''
    $lines += '## Next Steps'
    $lines += ''
    if (@($NextSteps).Count -eq 0) {
        $lines += '- Review high and critical findings first.'
        $lines += '- Check raw evidence before making changes.'
        $lines += '- Treat missing data as partial collection, not proof of absence.'
    } else {
        foreach ($step in $NextSteps) {
            $lines += "- $(ConvertTo-OpsForgeText $step)"
        }
    }

    [string[]]$reportLines = @($lines | ForEach-Object { ConvertTo-OpsForgeText $_ })
    Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutputDirectory 'report.md') -Value $reportLines
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

function ConvertTo-OpsForgeText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        return (@($Value) | ForEach-Object { [string]$_ }) -join '; '
    }

    return [string]$Value
}

function Get-OpsForgeObjectField {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return ''
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return ''
    }

    return ConvertTo-OpsForgeText $property.Value
}

function Get-OpsForgeIdSeed {
    param([AllowNull()][object]$Value)

    $text = ConvertTo-OpsForgeText $Value
    $hash = [int64]$text.GetHashCode()
    if ($hash -lt 0) {
        $hash = -$hash
    }
    return $hash
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
