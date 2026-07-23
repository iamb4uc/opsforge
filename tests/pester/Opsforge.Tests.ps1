Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Describe 'opsforge PowerShell scripts' {
    BeforeAll {
        $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    }

    It 'parse without syntax errors' {
        $files = Get-ChildItem -Path (Join-Path $script:RepoRoot 'bin'), (Join-Path $script:RepoRoot 'lib'), (Join-Path $script:RepoRoot 'scripts') -Recurse -File -Include *.ps1
        $messages = @()

        foreach ($file in $files) {
            $tokens = $null
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
            foreach ($parserError in $errors) {
                $messages += ('{0}:{1}:{2}: {3}' -f $file.FullName, $parserError.Extent.StartLineNumber, $parserError.Extent.StartColumnNumber, $parserError.Message)
            }
        }

        ($messages -join [Environment]::NewLine) | Should -Be ''
    }

    It 'dispatches only to scripts that exist' {
        $wrapper = Get-Content -Raw -Path (Join-Path $script:RepoRoot 'bin\opsforge.ps1')
        $paths = [regex]::Matches($wrapper, "Join-Path \$Root '([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        $missing = @()

        foreach ($path in $paths) {
            if (-not (Test-Path (Join-Path $script:RepoRoot $path))) {
                $missing += $path
            }
        }

        ($missing -join [Environment]::NewLine) | Should -Be ''
    }

    It 'keeps the windows dispatch flow aligned with the companion path' {
        $wrapper = Get-Content -Raw -Path (Join-Path $script:RepoRoot 'bin\opsforge.ps1')
        $patterns = @(
            "'windows:doctor' { Invoke-OpsForgeDoctor; break }",
            "'windows:quick' { Invoke-WindowsProfile -Profile 'quick'; break }",
            "'windows:ir' { Invoke-WindowsProfile -Profile 'ir'; break }",
            "'windows:full' { Invoke-WindowsProfile -Profile 'full'; break }",
            "'windows:all' { Invoke-WindowsAll; break }",
            "'windows:triage' { Invoke-OpsForgeScript (Join-Path `$Root 'scripts\windows\endpoint\Invoke-WinTriage.ps1'); break }",
            "'windows:persistence' { Invoke-OpsForgeScript (Join-Path `$Root 'scripts\windows\persistence\Find-WinPersistence.ps1'); break }",
            "'windows:tasks' { Invoke-OpsForgeScript (Join-Path `$Root 'scripts\windows\persistence\Test-WinScheduledTasks.ps1'); break }",
            "'windows:network' { Invoke-OpsForgeScript (Join-Path `$Root 'scripts\windows\network\Get-WinNetworkExposure.ps1'); break }",
            "'windows:timeline' { Invoke-OpsForgeScript (Join-Path `$Root 'scripts\windows\forensic\New-WinEventTimeline.ps1'); break }"
        )

        $missing = foreach ($pattern in $patterns) {
            if (-not $wrapper.Contains($pattern)) {
                $pattern
            }
        }

        ($missing -join [Environment]::NewLine) | Should -Be ''
    }
}
