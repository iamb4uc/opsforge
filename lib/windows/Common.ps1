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
        Write-OpsForgeTextFile -Path $jsonPath -Lines @('[]')
    } else {
        Write-OpsForgeTextFile -Path $jsonPath -Lines @((@($Findings) | ConvertTo-Json -Depth 6))
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
    Write-OpsForgeTextFile -Path (Join-Path $OutputDirectory 'summary.txt') -Lines $lines
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

    try {
        $findingList = @($Findings)
        $statMap = Get-OpsForgeDictionary -InputObject $Stats
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

        Write-OpsForgeTextFile -Path (Join-Path $OutputDirectory 'report.md') -Lines $lines
    } catch {
        Save-OpsForgeReportError -OutputDirectory $OutputDirectory -Title $Title -Message $_.Exception.Message
    }
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

function Write-OpsForgeTextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyCollection()][object[]]$Lines = @()
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    [string[]]$safeLines = @($Lines | ForEach-Object { ConvertTo-OpsForgeText $_ })
    Set-Content -Encoding UTF8 -LiteralPath $Path -Value $safeLines
}

function Get-OpsForgeDictionary {
    param([AllowNull()][object]$InputObject)

    $map = @{}
    if ($null -eq $InputObject) {
        return $map
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            $map[(ConvertTo-OpsForgeText $key)] = $InputObject[$key]
        }
        return $map
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        $map[$property.Name] = $property.Value
    }
    return $map
}

function Save-OpsForgeReportError {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Message
    )

    Write-OpsForgeTextFile `
        -Path (Join-Path $OutputDirectory 'raw\report-write-error.txt') `
        -Lines @("Unable to write full report: $Message")

    Write-OpsForgeTextFile `
        -Path (Join-Path $OutputDirectory 'report.md') `
        -Lines @(
            "# $Title",
            '',
            "- Host: $(Get-OpsForgeHostName)",
            "- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
            '',
            '## Report Writer Error',
            '',
            "Unable to write full report: $Message",
            '',
            '## Evidence Files',
            '',
            '- raw\',
            '- findings.json',
            '- summary.txt',
            '- raw\report-write-error.txt'
        )
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
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
    } finally {
        $sha256.Dispose()
    }
    return [BitConverter]::ToString($hash, 0, 8).Replace('-', '').ToLowerInvariant()
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
