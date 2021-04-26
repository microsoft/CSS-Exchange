Function Test-OtherWellKnownObjects {
    [CmdletBinding()]
    param ()

    $rootDSE = [ADSI]("LDAP://RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)
    $filePath = "$PSScriptRoot\ExchangeContainerOriginal.txt"

    ldifde -d $exchangeContainerPath -p Base -l otherWellKnownObjects -f $filePath

    $ldifObjects = @(Get-Content $filePath | ConvertFrom-Ldif)

    if ($ldifObjects.Length -lt 1) {
        throw "Failed to export $([IO.Path]::GetFileName($filePath)) file"
    }

    if ($ldifObjects.Length -gt 1) {
        throw "Unexpected LDIF data."
    }

    $exchangeContainer = $ldifObjects[0]
    $badValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -like "*CN=Deleted Objects*" })
    if ($badValues.Length -gt 0) {
        "" | Receive-Output
        "otherWellKnownObjects contains the following deleted objects:" | Receive-Output -IsWarning
        "" | Receive-Output
        $badValues | ForEach-Object { $_ | Receive-Output }

        $outputLines = New-Object 'System.Collections.Generic.List[string]'
        $outputLines.Add("dn: " + $exchangeContainer.dn[0])
        $outputLines.Add("changeType: modify")
        $outputLines.Add("replace: otherWellKnownObjects")

        $goodValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -notlike "*CN=Deleted Objects*" })
        $goodValues | ForEach-Object { $outputLines.Add("otherWellKnownObjects: " + $_) }
        $outputLines.Add("-")
        $outputLines.Add("")
        $outputLines | Out-File -FilePath "ExchangeContainerImport.txt"

        "`r`nVerify the results in ExchangeContainerImport.txt. Then run the following command:" | Receive-Output
        "`r`n`tldifde -i -f ExchangeContainerImport.txt" | Receive-Output
        "`r`nThen, run Setup.exe /PrepareAD to recreate the deleted groups." | Receive-Output
        "" | Receive-Output
    } else {
        "No bad values found in otherWellKnownObjects." | Receive-Output
        Remove-Item $filePath -Force
    }

    return
}
