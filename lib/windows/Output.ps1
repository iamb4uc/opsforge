#Requires -Version 5.1
Set-StrictMode -Version Latest

function Save-OpsForgeMarkdownTable {
    param(
        [Parameter(Mandatory = $true)][object[]]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($InputObject.Count -eq 0) {
        'No records.' | Set-Content -Encoding UTF8 -Path $Path
        return
    }
    $InputObject | ConvertTo-Csv -NoTypeInformation | Set-Content -Encoding UTF8 -Path $Path
}
