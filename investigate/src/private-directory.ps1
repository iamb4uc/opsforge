#Requires -Version 5.1
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$destination = $env:OPSFORGE_PRIVATE_DIRECTORY
$parent = [IO.Path]::GetDirectoryName($destination)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetOwner($identity)
$security.SetAccessRuleProtection($true, $false)
$rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$security.AddAccessRule($rule)
# Create with the private ACL, then reserve the requested name without overwrite.
$staging = [IO.Path]::Combine($parent, '.opsforge-private-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($staging, $security)
try {
    $actual = [IO.Directory]::GetAccessControl($staging)
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]) -ne $identity -or
        $rules.Count -ne 1 -or $rules[0].IdentityReference -ne $identity -or
        $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
        throw 'Filesystem did not retain the private ACL'
    }
    [IO.Directory]::Move($staging, $destination)
} catch {
    Write-Error "Private empty staging directory retained at ${staging}: $_"
    exit 1
}
