Function Test-OtherWellKnownObjects {
    [CmdletBinding()]
    param ()

    $rootDSE = [ADSI]("LDAP://RootDSE")
    $exchangeContainerPath = ("CN=Microsoft Exchange,CN=Services," + $rootDSE.configurationNamingContext)

    ldifde -d $exchangeContainerPath -p Base -l otherWellKnownObjects -f $PSScriptRoot\ExchangeContainerOriginal.txt

    $ldifObjects = @(Get-Content $PSScriptRoot\ExchangeContainerOriginal.txt | ConvertFrom-Ldif)

    if ($ldifObjects.Length -lt 1) {
        throw "Failed to export ExchangeContainerOriginal.txt file"
    }

    if ($ldifObjects.Length -gt 1) {
        throw "Unexpected LDIF data."
    }

    $exchangeContainer = $ldifObjects[0]
    $badValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -like "*CN=Deleted Objects*" })
    if ($badValues.Length -gt 0) {
        Write-Host
        Write-Warning "otherWellKnownObjects contains the following deleted objects:"
        Write-Host
        $badValues | ForEach-Object { Write-Host $_ }

        $outputLines = New-Object 'System.Collections.Generic.List[string]'
        $outputLines.Add("dn: " + $exchangeContainer.dn[0])
        $outputLines.Add("changeType: modify")
        $outputLines.Add("replace: otherWellKnownObjects")

        $goodValues = @($exchangeContainer.otherWellKnownObjects | Where-Object { $_ -notlike "*CN=Deleted Objects*" })
        $goodValues | ForEach-Object { $outputLines.Add("otherWellKnownObjects: " + $_) }
        $outputLines.Add("-")
        $outputLines.Add("")
        $outputLines | Out-File -FilePath "ExchangeContainerImport.txt"

        Write-Host("`r`nVerify the results in ExchangeContainerImport.txt. Then run the following command:")
        Write-Host("`r`n`tldifde -i -f ExchangeContainerImport.txt")
        Write-Host("`r`nThen, run Setup.exe /PrepareAD to recreate the deleted groups.")
        Write-Host
    } else {
        Write-Host "No bad values found in otherWellKnownObjects."
    }

    return
}