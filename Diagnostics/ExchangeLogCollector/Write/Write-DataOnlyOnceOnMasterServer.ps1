# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Write-DataOnlyOnceOnMasterServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Can not use using for an env variable')]
    param()
    Write-ScriptDebug("Enter Function: Write-DataOnlyOnceOnMasterServer")
    Write-ScriptDebug("Writing only once data")

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
        New-Folder -NewFolder $create -IncludeDisplayCreate $true
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
        Save-DataInfoToFile -DataIn $Script:ErrorsHandled -SaveToLocation ("$RootCopyToDirectory\HandledErrors")
    } else {
        Write-ScriptDebug ("No errors occurred within the script")
    }

    Write-ScriptDebug("Exiting Function: Write-DataOnlyOnceOnMasterServer")
}
