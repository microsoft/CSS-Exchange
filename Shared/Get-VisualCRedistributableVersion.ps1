Function Get-VisualCRedistributableVersion {
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: Get-VisualCRedistributableVersion"
        $softwareList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $installedSoftware = Invoke-ScriptBlockHandler -ComputerName $ComputerName `
            -ScriptBlock { Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* } `
            -ScriptBlockDescription "Querying for software" `
            -CatchActionFunction $CatchActionFunction

        foreach ($software in $installedSoftware) {

            if ($software.DisplayName -like "Microsoft Visual C++ *") {
                Write-Verbose "Microsoft Visual C++ Found: $($software.DisplayName)"
                $softwareList.Add([PSCustomObject]@{
                        DisplayName       = $software.DisplayName
                        DisplayVersion    = $software.DisplayVersion
                        InstallDate       = $software.InstallDate
                        VersionIdentifier = $software.Version
                    })
            }
        }
    }
    end {
        Write-Verbose "Exiting: Get-VisualCRedistributableVersion"
        return $softwareList
    }
}
