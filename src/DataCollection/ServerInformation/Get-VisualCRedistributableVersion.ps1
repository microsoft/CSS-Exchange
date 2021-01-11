Function Get-VisualCRedistributableVersion {

    Write-VerboseOutput("Calling: Get-VisualCRedistributableVersion")
    $installedSoftware = Invoke-ScriptBlockHandler -ComputerName $Script:Server -ScriptBlock { Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* } -ScriptBlockDescription "Quering for software" -CatchActionFunction ${Function:Invoke-CatchActions}
    $softwareInfos = @()

    foreach ($software in $installedSoftware) {

        if ($software.DisplayName -like "Microsoft Visual C++ *") {
            Write-VerboseOutput("Microsoft Visual C++ Redistributable found: {0}" -f $software.DisplayName)
            [HealthChecker.SoftwareInformation]$softwareInfo = New-Object Healthchecker.SoftwareInformation
            $softwareInfo.DisplayName = $software.DisplayName
            $softwareInfo.DisplayVersion = $software.DisplayVersion
            $softwareInfo.InstallDate = $software.InstallDate
            $softwareInfo.VersionIdentifier = $software.Version
            $softwareInfos += $softwareInfo
        }
    }

    Write-VerboseOutput("Exiting: Get-VisualCRedistributableVersion")
    return $softwareInfos
}