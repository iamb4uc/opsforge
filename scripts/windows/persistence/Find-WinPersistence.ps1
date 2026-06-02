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

$OutDir = New-OpsForgeOutputDirectory -OutputPath $OutputPath -ScriptName 'Find-WinPersistence'
$findings = New-Object System.Collections.Generic.List[object]
$autoruns = New-Object System.Collections.Generic.List[object]

function Add-CommandFinding {
    param([string]$Source, [string]$Name, [string]$Command)
    $seed = [Math]::Abs(("$Source-$Name-$Command").GetHashCode())
    if ($Command -match '(?i)\\AppData\\|\\Temp\\|\\Users\\Public\\|\\Windows\\Temp\\') {
        $findings.Add((New-OpsForgeFinding "WIN-PERSIST-USERPATH-$seed" 'Persistence entry points to user-writable path' 'high' 'persistence' "$Source $Name $Command" 'Validate the referenced binary and remove unauthorized autorun entries.'))
    }
    if ($Command -match '(?i)powershell.*(-enc|-encodedcommand)') {
        $findings.Add((New-OpsForgeFinding "WIN-PERSIST-ENC-$seed" 'Persistence entry uses encoded PowerShell' 'high' 'persistence' "$Source $Name $Command" 'Decode the command, preserve evidence, and disable unauthorized persistence.'))
    }
    if ($Command -match '(?i)(rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|wmic)\.exe') {
        $findings.Add((New-OpsForgeFinding "WIN-PERSIST-LOLBIN-$seed" 'Persistence entry uses a living-off-the-land binary' 'medium' 'persistence' "$Source $Name $Command" 'Confirm expected business use and inspect arguments for remote payload loading.'))
    }
}

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key
        foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $record = [pscustomobject]@{ Source = $key; Name = $prop.Name; Command = [string]$prop.Value }
            $autoruns.Add($record)
            Add-CommandFinding -Source $record.Source -Name $record.Name -Command $record.Command
        }
    }
}

$services = Get-CimInstance Win32_Service
foreach ($svc in $services) {
    $autoruns.Add([pscustomobject]@{ Source = 'Service'; Name = $svc.Name; Command = $svc.PathName })
    if ($svc.PathName -match '(?i)\\AppData\\|\\Temp\\|\\Users\\Public\\|powershell.*(-enc|-encodedcommand)') {
        Add-CommandFinding -Source 'Service' -Name $svc.Name -Command $svc.PathName
        $findings.Add((New-OpsForgeFinding "WIN-PERSIST-SERVICE-$([Math]::Abs($svc.Name.GetHashCode()))" 'Service has suspicious persistence path or arguments' 'high' 'persistence' "$($svc.Name) $($svc.PathName)" 'Validate service creation time, binary signature, and owner.'))
    }
}

Get-ScheduledTask | ForEach-Object {
    $action = ($_.Actions | ForEach-Object { Get-OpsForgeTaskActionText $_ }) -join '; '
    $autoruns.Add([pscustomobject]@{ Source = 'ScheduledTask'; Name = "$($_.TaskPath)$($_.TaskName)"; Command = $action })
    if ($_.Settings.Hidden) {
        $findings.Add((New-OpsForgeFinding "WIN-PERSIST-HIDDEN-TASK-$([Math]::Abs(($_.TaskPath + $_.TaskName).GetHashCode()))" 'Hidden scheduled task' 'medium' 'persistence' "$($_.TaskPath)$($_.TaskName)" 'Confirm task legitimacy and export XML for review.'))
    }
    Add-CommandFinding -Source 'ScheduledTask' -Name "$($_.TaskPath)$($_.TaskName)" -Command $action
}

$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Force -Path $folder | ForEach-Object {
            $autoruns.Add([pscustomobject]@{ Source = 'StartupFolder'; Name = $_.FullName; Command = $_.FullName })
            Add-CommandFinding -Source 'StartupFolder' -Name $_.Name -Command $_.FullName
        }
    }
}

$profileNames = @(
    'AllUsersAllHosts',
    'AllUsersCurrentHost',
    'CurrentUserAllHosts',
    'CurrentUserCurrentHost'
)
$profiles = @(
    foreach ($profileName in $profileNames) {
        $property = $PROFILE.PSObject.Properties[$profileName]
        if ($property -and $property.Value -and (Test-Path $property.Value)) {
            $property.Value
        }
    }
) | Select-Object -Unique
foreach ($profilePath in $profiles) {
    $content = Get-Content -Raw -Path $profilePath -ErrorAction SilentlyContinue
    $autoruns.Add([pscustomobject]@{ Source = 'PowerShellProfile'; Name = $profilePath; Command = $content })
    Add-CommandFinding -Source 'PowerShellProfile' -Name $profilePath -Command $content
}

$specialKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
)
foreach ($key in $specialKeys) {
    if (Test-Path $key) {
        Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -match 'Debugger|Shell|Userinit|AppInit_DLLs' } | ForEach-Object {
                $autoruns.Add([pscustomobject]@{ Source = $_.Name; Name = $key; Command = [string]$_.Value })
                Add-CommandFinding -Source $_.Name -Name $key -Command ([string]$_.Value)
            }
        }
    }
}

try {
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\wmi-event-consumers.json')
} catch {
    "Unable to read WMI event consumers: $($_.Exception.Message)" | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\wmi-event-consumers.error.txt')
}

$autoruns.ToArray() | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\autoruns.json')

try {
    Save-OpsForgeFindings -Findings $findings.ToArray() -OutputDirectory $OutDir
} catch {
    $message = "Unable to write findings cleanly: $($_.Exception.Message)"
    $message | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\findings-write-error.txt')
    '[]' | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'findings.json')
    '[]' | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'normalized\findings.json')
}

try {
    Save-OpsForgeReport `
        -OutputDirectory $OutDir `
        -Title 'Windows Persistence Hunter' `
        -Findings $findings.ToArray() `
        -Stats @{
            AutorunRecords = @($autoruns).Count
            PowerShellProfiles = @($profiles).Count
        } `
        -EvidenceFiles @(
            'raw\autoruns.json',
            'raw\wmi-event-consumers.json',
            'raw\wmi-event-consumers.error.txt'
        ) `
        -Limitations @(
            'Registry, WMI, and scheduled task visibility can be partial without admin rights.',
            'PowerShell profile paths vary between Windows PowerShell and PowerShell 7.'
        ) `
        -NextSteps @(
            'Start with AppData, Temp, encoded PowerShell, hidden task, and LOLBin findings.',
            'Export suspicious scheduled tasks and preserve referenced binaries before cleanup.'
        )
} catch {
    $message = "Unable to write full report: $($_.Exception.Message)"
    $message | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'raw\report-write-error.txt')
    @(
        '# Windows Persistence Hunter',
        '',
        "- Host: $env:COMPUTERNAME",
        "- Findings: $($findings.Count)",
        "- Autorun records: $(@($autoruns).Count)",
        '',
        '## Evidence Files',
        '',
        '- raw\autoruns.json',
        '- findings.json',
        '',
        '## Collection Limitations',
        '',
        "- $message",
        '- Registry, WMI, and scheduled task visibility can be partial without admin rights.',
        '',
        '## Next Steps',
        '',
        '- Review findings.json and raw\autoruns.json.',
        '- Preserve suspicious referenced files before cleanup.'
    ) | Set-Content -Encoding UTF8 -Path (Join-Path $OutDir 'report.md')
}
Save-OpsForgeSummary -OutputDirectory $OutDir -Title 'Windows persistence hunter' -FindingCount $findings.Count
Write-OpsForgeInfo -Message "Output written to $OutDir" -Quiet:$Quiet
