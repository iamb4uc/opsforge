#Requires -Version 5.1
Set-StrictMode -Version Latest

function Test-OpsForgeCommand {
    param([string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}
