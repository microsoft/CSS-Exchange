# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeOtherWellKnownObjects.ps1

function Test-DomainOtherWellKnownObjects {
    $exchangeContainer = Get-ExchangeContainer
    $otherWellKnownObjects = Get-ExchangeOtherWellKnownObjects

    $importFilePath = "$PSScriptRoot\ExchangeContainerImport.txt"
    $outputLines = New-Object 'System.Collections.Generic.List[string]'
    $outputLines.Add("dn: $($exchangeContainer.Properties["distinguishedName"][0].ToString())")
    $outputLines.Add("changeType: modify")
    $outputLines.Add("replace: otherWellKnownObjects")
    $badItemsFound = $false
    foreach ($value in $otherWellKnownObjects.RawValue) {

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
