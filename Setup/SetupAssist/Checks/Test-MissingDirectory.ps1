Function Test-MissingDirectory {
    $installPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath

    if ($null -ne $installPath -and
        (Test-Path $installPath)) {
        $paths = @("$installPath`UnifiedMessaging\Grammars", "$installPath`UnifiedMessaging\Prompts")

        foreach ($path in $paths) {

            if (!(Test-Path $path)) {
                "Failed to find path: '$path'. Create this or setup will fail" | Receive-Output -IsWarning
            }
        }
    }
}