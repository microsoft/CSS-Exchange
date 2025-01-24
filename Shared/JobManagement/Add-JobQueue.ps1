# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\GetJobManagementFunctions.ps1

<#
.SYNOPSIS
    Add a Job into the queue that is going to be using the cmdlet Invoke-Command -AsJob or Start-Job. You must provide the parameters that are used for the cmdlet,
    other than Invoke-Command where -AsJob will automatically be provided.
.DESCRIPTION
    TODO
.PARAMETER JobCommand
    The cmdlet that this job is going to be using to execute. Only options are Invoke-Command or Start-Job
.PARAMETER JobParameter
    The parameter that is going to be used with the JobCommand.
.PARAMETER JobId
    A unique ID for the job name. Recommended IDs are GUID-ServerName
.PARAMETER FriendlyName
    The friendly name of the job that can be used for Write-Progress
.PARAMETER Priority
    If you have a job that needs to go first, make sure that it is set to High. Valid Options High, Normal, Low

#>

function Add-JobQueue {
    [CmdletBinding()]
    param(
        [ValidateSet("Invoke-Command", "Start-Job")]
        [string]$JobCommand = "Invoke-Command",
        [Parameter(Mandatory = $true)]
        [object]$JobParameter,
        [Parameter(Mandatory = $true)]
        [string]$JobId,
        [string]$FriendlyName,
        [ValidateSet("High", "Normal", "Low")]
        [string]$Priority = "Normal"
    )
    begin {
        $getJobQueue = Get-JobQueue
    }
    process {
        $obj = [PSCustomObject]@{
            JobCommand   = $JobCommand
            JobParameter = $JobParameter
            JobId        = $JobId
            Priority     = $Priority
            JobStartTime = [DateTime]::MinValue
            JobEndTime   = [DateTime]::MinValue
            Job          = $null
            Results      = $null
            Error        = $null
        }

        if ($getJobQueue.ContainsKey($JobId)) {
            throw "Already contains the JobID: $JobId"
        }

        $getJobQueue.Add($JobId, $obj)
        Write-Verbose "Successfully added JobId: $JobId"
    }
}
