# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ExchangeServerInfo\Get-VirtualDirectoriesLdap.ps1
. $PSScriptRoot\..\RemoteScriptBlock\IO\Save-DataInfoToFile.ps1
function Write-DataOnlyOnceOnMasterServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Can not use using for an env variable')]
    param()
    Write-Verbose("Enter Function: Write-DataOnlyOnceOnMasterServer")
    Write-Verbose("Writing only once data")

    if (!$Script:MasterServer.ToUpper().Contains($env:COMPUTERNAME.ToUpper())) {
        $serverName = Invoke-Command -ComputerName $Script:MasterServer -ScriptBlock { return $env:COMPUTERNAME }
        $RootCopyToDirectory = "\\{0}\{1}" -f $Script:MasterServer, (("{0}{1}" -f $Script:RootFilePath, $serverName).Replace(":", "$"))
    } else {
        $RootCopyToDirectory = "{0}{1}" -f $Script:RootFilePath, $env:COMPUTERNAME
    }

    if ($GetVdirs -and (-not($Script:EdgeRoleDetected))) {
        $target = $RootCopyToDirectory + "\ConfigNC_msExchVirtualDirectory_All.CSV"
        $data = (Get-VirtualDirectoriesLdap)
        $data | Sort-Object -Property Server | Export-Csv $target -NoTypeInformation
    }

    if ($OrganizationConfig) {
        $target = $RootCopyToDirectory + "\OrganizationConfig"
        $data = Get-OrganizationConfig
        Save-DataInfoToFile -dataIn (Get-OrganizationConfig) -SaveToLocation $target -AddServerName $false
    }

    if ($SendConnectors) {
        $create = $RootCopyToDirectory + "\Connectors"
        New-Item -ItemType Directory -Path $create -Force | Out-Null
        $saveLocation = $create + "\Send_Connectors"
        Save-DataInfoToFile -dataIn (Get-SendConnector) -SaveToLocation $saveLocation -AddServerName $false
    }

    if ($TransportConfig) {
        $target = $RootCopyToDirectory + "\TransportConfig"
        $data = Get-TransportConfig
        Save-DataInfoToFile -dataIn $data -SaveToLocation $target -AddServerName $false
    }

    if ($Error.Count -ne 0) {
        Save-DataInfoToFile -DataIn $Error -SaveToLocation ("$RootCopyToDirectory\AllErrors")
        Save-DataInfoToFile -DataIn (Get-UnhandledErrors) -SaveToLocation ("$RootCopyToDirectory\UnhandledErrors")
        Save-DataInfoToFile -DataIn (Get-HandledErrors) -SaveToLocation ("$RootCopyToDirectory\HandledErrors")
    } else {
        Write-Verbose ("No errors occurred within the script")
    }

    Write-Verbose("Exiting Function: Write-DataOnlyOnceOnMasterServer")
}
