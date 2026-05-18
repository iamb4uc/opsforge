#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('parser','static','wrapper-targets','runtime','all','help')][string]$Command = 'help'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$TestRoot = if ($env:OPSFORGE_TEST_OUTPUT) { $env:OPSFORGE_TEST_OUTPUT } else { Join-Path $Root '.ci-artifacts' }

function Write-TestLine {
    param([string]$Message)
    Write-Host "[test] $Message"
}

function Fail-Test {
    param([string]$Message)
    throw "[test] ERROR: $Message"
}

function Show-Usage {
    @'
Usage:
  .\bin\test.ps1 parser
  .\bin\test.ps1 static
  .\bin\test.ps1 wrapper-targets
  .\bin\test.ps1 runtime
  .\bin\test.ps1 all
'@ | Write-Host
}

function New-TestRunDirectory {
    param([string]$Name)
    New-Item -ItemType Directory -Force -Path $TestRoot | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path $TestRoot "$Name-$stamp"
    $candidate = $dir
    $counter = 1
    while (Test-Path $candidate) {
        $counter++
        $candidate = "$dir-$counter"
    }
    New-Item -ItemType Directory -Force -Path $candidate | Out-Null
    return (Resolve-Path $candidate).Path
}

function Get-FindingCount {
    param([string]$Path)
    $json = Get-Content -Raw -Path $Path | ConvertFrom-Json
    return @($json).Count
}

function Test-OutputContract {
    param([string]$OutputDirectory)

    if (-not (Test-Path -Path $OutputDirectory -PathType Container)) { Fail-Test "missing output dir: $OutputDirectory" }
    foreach ($dir in @('raw','normalized')) {
        $path = Join-Path $OutputDirectory $dir
        if (-not (Test-Path -Path $path -PathType Container)) { Fail-Test "missing directory: $path" }
    }
    foreach ($file in @('report.md','findings.json','summary.txt','normalized\findings.json')) {
        $path = Join-Path $OutputDirectory $file
        if (-not (Test-Path -Path $path -PathType Leaf)) { Fail-Test "missing file: $path" }
        if ((Get-Item $path).Length -eq 0) { Fail-Test "empty file: $path" }
    }

    $rootFindings = Get-Content -Raw -Path (Join-Path $OutputDirectory 'findings.json')
    $normalizedFindings = Get-Content -Raw -Path (Join-Path $OutputDirectory 'normalized\findings.json')
    if ($rootFindings -ne $normalizedFindings) { Fail-Test "normalized findings differ: $OutputDirectory" }

    $findings = $rootFindings | ConvertFrom-Json
    foreach ($finding in @($findings)) {
        foreach ($key in @('id','title','severity','host','category','evidence','recommendation')) {
            if (-not ($finding.PSObject.Properties.Name -contains $key)) { Fail-Test "finding missing ${key}: $OutputDirectory" }
        }
        if ($finding.severity -notin @('critical','high','medium','low','info')) {
            Fail-Test "invalid severity '$($finding.severity)': $OutputDirectory"
        }
    }

    $summary = Get-Content -Path (Join-Path $OutputDirectory 'summary.txt')
    if (-not ($summary | Select-String -SimpleMatch 'Output:')) { Fail-Test "summary missing Output line: $OutputDirectory" }
    $findingLine = $summary | Where-Object { $_ -match '^Findings:\s*\d+' } | Select-Object -First 1
    if (-not $findingLine) { Fail-Test "summary missing Findings count: $OutputDirectory" }
    $summaryCount = [int]($findingLine -replace '^Findings:\s*','')
    $actualCount = Get-FindingCount -Path (Join-Path $OutputDirectory 'findings.json')
    if ($summaryCount -ne $actualCount) { Fail-Test "summary count $summaryCount != findings count $actualCount`: $OutputDirectory" }
}

function Get-LatestOutputDirectory {
    param([string]$Base, [string]$ScriptName)
    Get-ChildItem -Path $Base -Directory |
        Where-Object { $_.Name -like "*-$ScriptName-*" } |
        Sort-Object LastWriteTime |
        Select-Object -Last 1 -ExpandProperty FullName
}

function Test-Parser {
    Write-TestLine 'checking powershell parser'
    $files = Get-ChildItem -Path (Join-Path $Root 'bin'), (Join-Path $Root 'lib'), (Join-Path $Root 'scripts'), (Join-Path $Root 'tests\pester') -Recurse -File -Include *.ps1
    $messages = @()
    foreach ($file in $files) {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        foreach ($parserError in $errors) {
            $messages += ('{0}:{1}:{2}: {3}' -f $file.FullName, $parserError.Extent.StartLineNumber, $parserError.Extent.StartColumnNumber, $parserError.Message)
        }
    }
    if ($messages.Count -gt 0) { Fail-Test ($messages -join [Environment]::NewLine) }
}

function Test-Static {
    Write-TestLine 'checking windows script basics'
    $files = Get-ChildItem -Path (Join-Path $Root 'scripts\windows') -Recurse -File -Filter *.ps1
    foreach ($file in $files) {
        $content = Get-Content -Raw -Path $file.FullName
        if ($content -notmatch '\[CmdletBinding\(\)\]') { Fail-Test "missing CmdletBinding block: $($file.FullName)" }
        if ($content -notmatch '\[string\]\$OutputPath') { Fail-Test "missing OutputPath parameter: $($file.FullName)" }
        if ($content -notmatch '\[switch\]\$Quiet') { Fail-Test "missing Quiet parameter: $($file.FullName)" }
    }
}

function Test-WrapperTargets {
    Write-TestLine 'checking powershell wrapper targets'
    $wrapper = Get-Content -Raw -Path (Join-Path $Root 'bin\opsforge.ps1')
    $paths = [regex]::Matches($wrapper, 'Join-Path \$Root ''([^'']+)''') | ForEach-Object { $_.Groups[1].Value }
    foreach ($path in $paths) {
        $target = Join-Path $Root $path
        if (-not (Test-Path $target)) { Fail-Test "wrapper references missing script: $path" }
    }
}

function Invoke-SafeRuntimeCheck {
    param(
        [string]$Name,
        [string[]]$Arguments,
        [string]$ScriptName,
        [string]$OutputRoot
    )
    Write-Host "::group::$Name"
    try {
        $wrapperArgs = @($Arguments) + @('-OutputPath', $OutputRoot, '-Quiet')
        & (Join-Path $Root 'bin\opsforge.ps1') @wrapperArgs
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { Fail-Test "$Name exited with $LASTEXITCODE" }
        $outDir = Get-LatestOutputDirectory -Base $OutputRoot -ScriptName $ScriptName
        if (-not $outDir) { Fail-Test "$Name did not create output" }
        Test-OutputContract -OutputDirectory $outDir
    } finally {
        Write-Host "::endgroup::"
    }
}

function Test-Runtime {
    Write-TestLine 'running safe windows runtime checks'
    $outputRoot = New-TestRunDirectory -Name 'windows-runtime'
    Invoke-SafeRuntimeCheck -Name 'network' -Arguments @('windows','network') -ScriptName 'Get-WinNetworkExposure' -OutputRoot $outputRoot
    Invoke-SafeRuntimeCheck -Name 'tasks' -Arguments @('windows','tasks') -ScriptName 'Test-WinScheduledTasks' -OutputRoot $outputRoot
    Invoke-SafeRuntimeCheck -Name 'services' -Arguments @('windows','services') -ScriptName 'Test-WinServiceAnomaly' -OutputRoot $outputRoot
    Write-TestLine "windows runtime evidence: $outputRoot"
}

switch ($Command) {
    'parser' { Test-Parser }
    'static' { Test-Static }
    'wrapper-targets' { Test-WrapperTargets }
    'runtime' { Test-Runtime }
    'all' {
        Test-Parser
        Test-Static
        Test-WrapperTargets
        Test-Runtime
    }
    'help' { Show-Usage }
}
