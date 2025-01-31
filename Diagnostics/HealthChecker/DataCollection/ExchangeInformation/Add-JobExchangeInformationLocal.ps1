# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Helpers\Get-HCDefaultSBInjection.ps1

function Add-JobExchangeInformationLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    process {
        <#
            Non Default Script Block Dependencies
        #>
        function Invoke-JobExchangeInformationLocal {
            [CmdletBinding()]
            param()
            begin {
                # Build Process to add functions.
                . $PSScriptRoot\Get-ExchangeDependentServices.ps1

                if ($PSSenderInfo) {
                    $Script:ErrorsExcluded = @()
                }
            }
            process {
                $windows2016OrGreater = [environment]::OSVersion.Version -ge "10.0.0.0"

                if ($PSSenderInfo) {
                    $jobHandledErrors = $Script:ErrorsExcluded
                }
            }
            end {
                Write-Verbose "Completed: $($MyInvocation.MyCommand)"
                [PSCustomObject]@{
                    RemoteJob        = $true -eq $PSSenderInfo
                    JobHandledErrors = $jobHandledErrors
                }
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $sbInjectionParams = @{
            PrimaryScriptBlock = ${Function:Invoke-JobExchangeInformationLocal}
            IncludeScriptBlock = @()
        }
        $scriptBlock = Get-HCDefaultSBInjection @sbInjectionParams
        $params = @{
            JobParameter = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scriptBlock
            }
            JobId        = "cb563125-6cb9-4da9-9cde-241ee4f76332-$ComputerName"
        }
        Add-JobQueue @params
    }
}
