Function Test-MissingMsiFiles {
    $products = Get-ChildItem Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products
    $packageFiles = $products | ForEach-Object { Get-ItemProperty -Path "Registry::$($_.Name)\InstallProperties" -ErrorAction SilentlyContinue } | ForEach-Object { $_.LocalPackage }
    $packagesMissing = @($packageFiles | Where-Object { (Test-Path $_) -eq $false })

    if ($packagesMissing.Count -eq 0) {
        "No installer packages missing." | Receive-Output
    } else {
        "$($packagesMissing.Count) installer packages are missing. Please use this script to repair the installer folder:" | Receive-Output -IsWarning
        "https://gallery.technet.microsoft.com/office/Restore-the-Missing-d11de3a1" | Receive-Output -IsWarning
    }
}