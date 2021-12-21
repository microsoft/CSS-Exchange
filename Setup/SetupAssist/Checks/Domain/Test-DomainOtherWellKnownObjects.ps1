# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
Function Test-OtherWellKnownObjects {
    $rootDSE = [ADSI]("LDAP://RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $exchangeContainer = [ADSI]("LDAP://" + $exchangeContainerPath)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=*)", @("otherWellKnownObjects", "distinguishedName"))
    $result = $searcher.FindOne()

    $importFilePath = "$PSScriptRoot\ExchangeContainerImport.txt"
    $outputLines = New-Object 'System.Collections.Generic.List[string]'
    $outputLines.Add("dn: $($result.Properties["distinguishedName"][0].ToString())")
    $outputLines.Add("changeType: modify")
    $outputLines.Add("replace: otherWellKnownObjects")
    $badItemsFound = $false
    foreach ($value in $result.Properties["otherWellKnownObjects"]) {

        $params = @{
            TestName = "Other Well Known Objects"
            Details  = $value
        }

        if ($value -like "*CN=Deleted Objects*") {
            $badItemsFound = $true
            New-TestResult @params -Result "Failed" -ReferenceInfo (
                "Verify the results in $importFilePath. Then run the following command:`n`n" +
                "     ldifde -i -f $importFilePath`n`n" +
                "Then, run Setup.exe /PrepareAD to recreate the deleted groups.")
        } else {
            $outputLines.Add("otherWellKnownObjects: $value")
            New-TestResult @params -Result "Passed"
        }
    }

    if ($badItemsFound) {
        $outputLines.Add("-")
        $outputLines.Add("")
        $outputLines | Out-File -FilePath $importFilePath
    }
}
