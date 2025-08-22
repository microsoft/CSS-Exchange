# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1
. $PSScriptRoot\..\..\Helpers\Invoke-DefaultConnectExchangeShell.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-ExchangeContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\ActiveDirectoryFunctions\Get-OrganizationContainer.ps1
. $PSScriptRoot\..\..\..\..\Shared\Get-MonitoringOverride.ps1
. $PSScriptRoot\Invoke-JobExchangeInformationCmdlet.ps1

<#
.DESCRIPTION
    This process takes all the Exchange Servers that were passed to it and breaks up the list into manageable group.
    We need to do this because loading EMS can take time so it is faster to process multiple servers on a single session.
    Because the servers are grouped together, you must pass in a hashtable to be able to find the server data.
    The hashtable uses the server name as the key and the value is going to be name of the Job Id where the server will be located.
#>
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

        <#
            Here is how we determine how many servers per job we should handle.
            We balance the number of servers out based off the max job size.
            Example: defaultOptimizedServerToJobSize = 8. You have a list of 17 servers, we will optimize the grouping of servers to
                2 groups of 6 servers and 1 group of 5 servers.
        #>
        $jobNumbers = [System.Math]::Ceiling($exchangeServerList.Count / $Script:defaultOptimizedServerToJobSize )
        $maxServers = [System.Math]::Ceiling($exchangeServerList.Count / $jobNumbers)
        $argumentListValues = New-Object System.Collections.Generic.List[string[]]
        $tempListValues = New-Object System.Collections.Generic.List[string]
        $index = 0
        $serversAdded = 0
        $indexJobMatch = @{}

        while ($index -lt $exchangeServerList.Count) {

            # Once we get to our maxServers limit, we reset our lists that we need to add.
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
                JobCommand   = "Start-Job" # Start-Job is required to do EMS & LDAP queries.
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
