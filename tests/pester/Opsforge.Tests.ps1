Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')

Describe 'opsforge PowerShell scripts' {
    It 'parse without syntax errors' {
        $files = Get-ChildItem -Path (Join-Path $RepoRoot 'bin'), (Join-Path $RepoRoot 'lib'), (Join-Path $RepoRoot 'scripts') -Recurse -File -Include *.ps1
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
        $wrapper = Get-Content -Raw -Path (Join-Path $RepoRoot 'bin\opsforge.ps1')
        $paths = [regex]::Matches($wrapper, "Join-Path \$Root '([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        $missing = @()

        foreach ($path in $paths) {
            if (-not (Test-Path (Join-Path $RepoRoot $path))) {
                $missing += $path
            }
        }

        ($missing -join [Environment]::NewLine) | Should -Be ''
    }
}
