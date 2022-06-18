# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1

# Method to set require SSL flag for a Virtual Directory
function Set-SSLFlag {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Logic not yet implemented to consider PSShouldProcess - future work.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter (Mandatory = $true, Position=0)]
        [string]$Server,
        [Parameter (Mandatory = $true, Position=1)]
        [string]$website_name,
        [Parameter (Mandatory = $true, Position=2)]
        [string]$vdirname
    )

    # This function will be called by the script block to set require ssl flag on different server
    function SetSSLFlagDetailsScriptBlock {
        param(
            [Parameter (Mandatory = $true, Position=0)]
            [string]$Server,
            [Parameter (Mandatory = $true, Position=1)]
            [string]$website_name,
            [Parameter (Mandatory = $true, Position=2)]
            [string]$vdirname
        )
        Set-WebConfigurationProperty -Filter "system.WebServer/security/access" -Name sslflags -Value "Ssl, Ssl128" -PSPath "IIS:\" -Location "$website_name/$vdirname"
    }

    Invoke-ScriptBlockHandler -ComputerName $Server -ScriptBlock ${Function:SetSSLFlagDetailsScriptBlock} -ArgumentList ($Server, $website_name, $vdirname) -ScriptBlockDescription "Setting the require SSL Flag on the server $Server, $Website_Name, $vdirname."
}
