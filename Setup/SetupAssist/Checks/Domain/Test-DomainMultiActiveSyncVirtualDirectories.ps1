# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-OrganizationContainer.ps1

Function Test-DomainMultiActiveSyncVirtualDirectories {
    $params = @{
        TestName = "Multiple Active Sync Vdirs Detected"
    }
    $orgContainer = Get-OrganizationContainer
    $orgDN = $orgContainer.Properties["distinguishedName"]
    $containerPath = [ADSI]("LDAP://CN=$env:ComputerName,CN=Servers,CN=Exchange administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,$orgDN")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($containerPath, "(objectClass=msExchMobileVirtualDirectory)", @("distinguishedName"))
    $result = $searcher.FindAll()
    $fe = $result | Where-Object { $_.Properties["distinguishedName"] -notlike "*(Exchange Back End)*" }

    if ($fe.Count -gt 1) {
        $fe | ForEach-Object {
            New-TestResult @params -Result "Failed" -Details $_.Properties["distinguishedName"] -ReferenceInfo ("Remove the secondary virtual directory that is custom on the server")
        }
    } else {
        New-TestResult @params -Result "Passed"
    }
}
