# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

# Method to get the require SSL flag for the Virtual Directory
function Get-SSLFlag {
    param(
        [Parameter (Mandatory = $true, Position=0)]
        [string]$Server,
        [Parameter (Mandatory = $true, Position=1)]
        [string]$Website_Name,
        [Parameter (Mandatory = $true, Position=2)]
        [string]$VDirName
    )

    # This function will be called by the script block to get require ssl flag for the different server
    function GetSSLFlagScriptBlock {
        param(
            [Parameter (Mandatory = $true, Position=0)]
            [string]$Server,
            [Parameter (Mandatory = $true, Position=1)]
            [string]$Website_Name,
            [Parameter (Mandatory = $true, Position=2)]
            [string]$VDirName
        )
        Get-WebConfigurationProperty -Filter "system.WebServer/security/access" -Name sslflags -PSPath IIS:\ -Location "$Website_Name/$VDirName"
    }

    $sslFlagDetails = Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:GetSSLFlagScriptBlock} -ArgumentList ($Server, $Website_Name, $VDirName) -ScriptBlockDescription "Getting require SSL enabled Flag for $Server, $Website_Name, $VDirName."

    if ($sslFlagDetails.GetType().Name -ne "String") {
        return $sslFlagDetails.Value
    }
    return $sslFlagDetails
}
