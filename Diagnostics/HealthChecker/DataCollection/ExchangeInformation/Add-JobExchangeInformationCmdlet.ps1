# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1

function Add-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$ComputerName,

        # TODO: This is going to need to completely change
        [Parameter(Mandatory = $true)]
        [ValidateSet("Legacy", "Queue")]
        [string]$RunType
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeServerList = New-Object System.Collections.Generic.List[string]
        $legacyResults = @{}
    }
    process {
        foreach ($name in $ComputerName) {
            $exchangeServerList.Add($name)
        }
    }
    end {
        <#
            Non Default Script Block Dependencies
                Invoke-DefaultConnectExchangeShell
                Get-ExchangeContainer
                Get-MonitoringOverride
                Get-RemoteRegistrySubKey
        #>
        . $PSScriptRoot\Invoke-JobExchangeInformationCmdlet.ps1

        if ($RunType -eq "Legacy") {

            foreach ($name in $exchangeServerList) {
                $data = Invoke-JobExchangeInformationCmdlet -Server $name
                $legacyResults.Add("Invoke-JobExchangeInformationCmdlet-$name", $data)
            }
            return $legacyResults
        } else {
            # only thing we have right now is queue.
            $sbInjectionParams = @{
                PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationCmdlet}
                IncludeScriptBlock = @(${Function:Invoke-DefaultConnectExchangeShell}, ${Function:Get-ExchangeContainer},
                    ${Function:Get-MonitoringOverride})
            }
            $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
            $params = @{
                JobCommand   = "Start-Job"
                JobParameter = @{
                    ScriptBlock  = $scriptBlock
                    ArgumentList = $ComputerName
                }
                JobId        = "Invoke-JobExchangeInformationCmdlet-$ComputerName"
            }
            Add-JobQueue @params
        }
    }
}
