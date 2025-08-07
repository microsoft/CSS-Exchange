# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-OrganizationContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1
. $PSScriptRoot\Invoke-JobExchangeInformationCmdlet.ps1

function Add-JobExchangeInformationCmdlet {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$ComputerName,

        [ref]$JobKeyMatchingToServer
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $exchangeServerList = New-Object System.Collections.Generic.List[string]
    }
    process {
        foreach ($name in $ComputerName) {
            $exchangeServerList.Add($name)
        }
    }
    end {

        $nonDefaultSbDependencies = @(
            ${Function:ConvertTo-ExchangeCertificate},
            ${Function:Get-ExchangeContainer},
            ${Function:Get-MonitoringOverride},
            ${Function:Get-OrganizationContainer},
            ${Function:Invoke-DefaultConnectExchangeShell}
        )

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationCmdlet}
            IncludeScriptBlock = $nonDefaultSbDependencies
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams

        $jobNumbers = [System.Math]::Ceiling($exchangeServerList.Count / $Script:defaultOptimizedServerToJobSize )
        $maxServers = [System.Math]::Ceiling($exchangeServerList.Count / $jobNumbers)
        $argumentListValues = New-Object System.Collections.Generic.List[string[]]
        $tempListValues = New-Object System.Collections.Generic.List[string]
        $index = 0
        $serversAdded = 0
        $indexJobMatch = @{}

        while ($index -lt $exchangeServerList.Count) {

            if ($serversAdded -ge $maxServers) {
                $argumentListValues.Add($tempListValues)
                $tempListValues = New-Object System.Collections.Generic.List[string]
                $serversAdded = 0
            }
            $tempListValues.Add($exchangeServerList[$index])
            $indexJobMatch.Add($exchangeServerList[$index], $argumentListValues.Count)
            $serversAdded++
            $index++
        }
        $argumentListValues.Add($tempListValues)
        $indexJobMatch.Keys | ForEach-Object {
            $JobKeyMatchingToServer.Value.Add($_, "Invoke-JobExchangeInformationCmdlet-$(($argumentListValues[$indexJobMatch[$_]]).GetHashCode())")
        }

        foreach ($argumentList in $argumentListValues) {
            $params = @{
                JobCommand   = "Start-Job"
                JobParameter = @{
                    ScriptBlock  = $scriptBlock
                    ArgumentList = (, @($argumentList))
                }
                JobId        = "Invoke-JobExchangeInformationCmdlet-$($argumentList.GetHashCode())"
                TryStartNow  = $true
            }
            Add-JobQueue @params
        }
    }
}
