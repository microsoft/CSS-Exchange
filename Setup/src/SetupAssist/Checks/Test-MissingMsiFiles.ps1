Function Test-MissingMsiFiles {

    $packageFiles = Get-InstallerPackages -FilterDisplayName @("Microsoft Lync Server", "Exchange", "Microsoft Server Speech", "Microsoft Unified Communications")
    $packagesMissing = @($packageFiles | Where-Object { $_.ValidMsi -eq $false })

    if ($packagesMissing.Count -eq 0) {
        "No installer packages missing." | Receive-Output
    } else {
        "$($packagesMissing.Count) installer packages are missing. Please use this script to repair the installer folder:" | Receive-Output -IsWarning
        "https://aka.ms/ExInstallerCacheFix" | Receive-Output -IsWarning
    }
}