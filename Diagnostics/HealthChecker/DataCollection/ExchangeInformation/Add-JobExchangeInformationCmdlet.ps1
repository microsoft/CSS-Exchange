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
        [ValidateSet("Legacy", "Queue", "QueueOptimize")]
        [string]$RunType,

        [ref]$JobKeyMatchingToServer
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

        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationCmdlet}
            IncludeScriptBlock = @(${Function:Invoke-DefaultConnectExchangeShell}, ${Function:Get-ExchangeContainer},
                ${Function:Get-MonitoringOverride})
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams

        if ($RunType -eq "Legacy") {

            foreach ($name in $exchangeServerList) {
                $data = Invoke-JobExchangeInformationCmdlet -ServerName $name
                $legacyResults.Add("Invoke-JobExchangeInformationCmdlet-$name", $data)
            }
            return $legacyResults
        } elseif ($RunType -eq "Queue") {

            foreach ($name in $exchangeServerList) {
                $params = @{
                    JobCommand   = "Start-Job"
                    JobParameter = @{
                        ScriptBlock  = $scriptBlock
                        ArgumentList = $name
                    }
                    JobId        = "Invoke-JobExchangeInformationCmdlet-$name"
                }
                Add-JobQueue @params
            }
        } elseif ($RunType -eq "QueueOptimize") {
            $jobNumbers = [System.Math]::Ceiling($exchangeServerList.Count / 8 )
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
}
