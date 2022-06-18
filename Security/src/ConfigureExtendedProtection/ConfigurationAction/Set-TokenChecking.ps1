# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

# Method to set Extended Protection as Require/Accept for a Virtual Directory
function Set-TokenChecking {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Logic not yet implemented to consider PSShouldProcess - future work.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter (Mandatory = $true)]
        [string]$Server,
        [Parameter (Mandatory = $true)]
        [string]$Website_Name,
        [Parameter (Mandatory = $true)]
        [string]$VDirName,
        [Parameter (Mandatory = $true)]
        [string]$TokenChecking
    )

    # This function will be called by the script block to configure extended protection on different server
    function SetTokenCheckingScriptBlock {
        param(
            [Parameter (Mandatory = $true, Position=0)]
            [string]$Server,
            [Parameter (Mandatory = $true, Position=1)]
            [string]$Website_Name,
            [Parameter (Mandatory = $true, Position=2)]
            [string]$VDirName,
            [Parameter (Mandatory = $true, Position=3)]
            [string]$Token
        )

        Set-WebConfigurationProperty -Filter "system.WebServer/security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking -Value $Token -Location "$Website_Name/$VDirName" -PSPath IIS:\
    }

    Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:SetTokenCheckingScriptBlock} -ArgumentList ($Server, $Website_Name, $VDirName, $TokenChecking) -ScriptBlockDescription "Setting the extended protection to $TokenChecking on the server $Server, $Website_Name, $VDirName."
}
