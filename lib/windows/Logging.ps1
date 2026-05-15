#Requires -Version 5.1
Set-StrictMode -Version Latest

function Write-OpsForgeInfo {
    param([string]$Message, [switch]$Quiet)
    if (-not $Quiet) {
        Write-Host "[INFO] $Message"
    }
}
