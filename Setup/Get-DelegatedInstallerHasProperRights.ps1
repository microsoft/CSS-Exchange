# Get-DelegatedInstallerHasProperRights.ps1
#
# Identifies the issue described in https://support.microsoft.com/en-us/help/2961741
# by reading the setup log to see if this is why we failed.
#
# The article says this was fixed, but the fix was to add the Server Management
# group. The options are either add the delegated installer to that group, or
# remove them from whatever group is giving them too many rights (usually Domain Admins).

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [System.IO.FileInfo]$SetupLog)

if (-not ([IO.File]::Exists($SetupLog))) {
    Write-Error "Could not find file: $SetupLog"
    return
}

$enterpriseAdminCheck = Select-String "Evaluated \[Setting:EnterpriseAdmin\].+\[Value:`"(\w+)`"`]" $SetupLog | Select-Object -Last 1
$enterpriseAdminValue = $enterpriseAdminCheck.Matches.Groups[1].Value

if ($enterpriseAdminValue -eq "True") {
    Write-Host "User that ran setup has EnterpriseAdmin and does not need to be in Server Management."
    return
}
elseif ($enterpriseAdminValue -ne "False") {
    Write-Error "EnterpriseAdmin check has unexpected value: $enterpriseAdminValue"
    return
}

$exOrgAdminCheck = Select-String "Evaluated \[Setting:ExOrgAdmin\].+\[Value:`"(\w+)`"`]" $SetupLog | Select-Object -Last 1
$exOrgAdminValue = $exOrgAdminCheck.Matches.Groups[1].Value

if ($exOrgAdminValue -eq "True") {
    Write-Host "User that ran setup has ExOrgAdmin and does not need to be in Server Management."
    return
}
elseif ($exOrgAdminValue -ne "False") {
    Write-Error "ExOrgAdmin check has unexpected value: $exOrgAdminValue"
    return
}

$serverAlreadyExistsCheck = Select-String "Evaluated \[Setting:ServerAlreadyExists\].+\[Value:`"(\w+)`"`]" $SetupLog | Select-Object -Last 1
$serverAlreadyExistsValue = $serverAlreadyExistsCheck.Matches.Groups[1].Value

if ($serverAlreadyExistsValue -eq "False") {
    Write-Error "ServerAlreadyExists check came back False, and the user that ran setup does not have ExOrgAdmin or EnterpriseAdmin."
    return
}
elseif ($serverAlreadyExistsValue -ne "True") {
    Write-Error "ServerAlreadyExists check has unexpected value: $serverAlreadyExistsValue"
    return
}

$hasServerDelegatedPermsBlockedCheck = Select-String "Evaluated \[Setting:HasServerDelegatedPermsBlocked\].+\[Value:`"(\w+)`"`]" $SetupLog | Select-Object -Last 1
$hasServerDelegatedPermsBlockedValue = $null

if ($null -ne $hasServerDelegatedPermsBlockedCheck -and $null -ne $hasServerDelegatedPermsBlockedCheck.Matches) {
    $hasServerDelegatedPermsBlockedValue = $hasServerDelegatedPermsBlockedCheck.Matches.Groups[1].Value
}

if ($null -eq $hasServerDelegatedPermsBlockedValue) {
    Write-Host "HasServerDelegatedPermsBlocked returned no rights. This means the user that ran setup" `
        "does not have extra rights, and thus does not need to be in Server Management."
    return
}

$serverManagementCheck = Select-String "Evaluated \[Setting:ServerManagement\].+\[Value:`"(\w+)`"`]" $SetupLog | Select-Object -Last 1
$serverManagementValue = $serverManagementCheck.Matches.Groups[1].Value

if ($serverManagementValue -eq "True") {
    Write-Host "User that ran setup has extra rights to the server object, but is also a member of Server Management, so it's fine."
    return
}
elseif ($serverManagementValue -eq "False") {
    Write-Error "User that ran setup has extra rights to the server object and is not in Server Management. This causes setup to fail."
    return
}
else {
    Write-Error "ServerManagement check has unexpected value: $serverManagementValue"
    return
}