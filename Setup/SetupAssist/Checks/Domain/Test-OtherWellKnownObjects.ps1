# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\New-TestResult.ps1
. $PSScriptRoot\..\..\Utils\ConvertFrom-Ldif.ps1
Function Test-OtherWellKnownObjects {
    $rootDSE = [ADSI]("LDAP://RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $filePath = "$PSScriptRoot\ExchangeContainerOriginal.txt"
    $importFilePath = "ExchangeContainerImport.txt"

    ldifde -d $exchangeContainerPath -p Base -l otherWellKnownObjects -f $filePath | Out-Null

    $ldifObjects = @(Get-Content $filePath | ConvertFrom-Ldif)

    if ($ldifObjects.Length -lt 1) {
        throw "Failed to export $([IO.Path]::GetFileName($filePath)) file"
    }

    if ($ldifObjects.Length -gt 1) {
        throw "Unexpected LDIF data."
    }

    $exchangeContainer = $ldifObjects[0]
    $otherWellKnownObjects = @($exchangeContainer.otherWellKnownObjects)
    $outputLines = New-Object 'System.Collections.Generic.List[string]'
    $outputLines.Add("dn: $($exchangeContainer.dn[0])")
    $outputLines.Add("changeType: modify")
    $outputLines.Add("replace: otherWellKnownObjects")
    $badItemsFound = $false
    foreach ($value in $otherWellKnownObjects) {

        $params = @{
            TestName = "Other Well Known Objects"
            Details  = $value
        }

        if ($value -like "*CN=Deleted Objects*") {
            $badItemsFound = $true
            New-TestResult @params -Result "Failed" -ReferenceInfo ("Verify the results in $importFilePath. Then run the following command:`r`n`t" + `
                    "ldifde -i -f $importFilePath`r`nThen, run Setup.exe /PrepareAD to recreate the deleted groups.")
        } else {
            $outputLines.Add("otherWellKnownObjects: $value")
            New-TestResult @params -Result "Passed"
        }
    }

    if ($badItemsFound) {
        $outputLines.Add("-")
        $outputLines.Add("")
        $outputLines | Out-File -FilePath $importFilePath
    } else {
        Remove-Item $filePath -Force
    }
}
