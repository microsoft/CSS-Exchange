# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function global:Step-ExPerfWizSize {
    <#

    .SYNOPSIS
    Increases the max size of the exPerfWiz file by 1

    .DESCRIPTION
    To work around an issue with where start-exPerfWiz might fail this will increment the max size by 1mb

    .PARAMETER Name
    Name of the Data Collector set

    Default Exchange_PerfWiz

    .PARAMETER Server
    Name of the server

    Default LocalHost

	.OUTPUTS
    none

    .EXAMPLE
    Increase the max size of the default local exPerfWiz by 1

    Step-ExPerfWizSize

    .EXAMPLE
    Increase the max size of a named remote exPerfWiz by 1

    Step-ExPerfWizSize -Name "My Collector Set" -Server RemoteServer-01

    #>

    [CmdletBinding()]
    param (
        [string]
        $Name = "Exchange_PerfWiz",

        [string]
        $Server = $env:ComputerName
    )

    # Step up the size of the PerfWiz by 1
    $perfMon = Get-ExPerfWiz -Name $Name -Server $Server
    $newSize = $perfMon.MaxSize + 1

    # increment the size
    [string]$logman = $null
    [string]$logman = logman update -name $Name -s $Server -max $newSize

    # If we find an error throw
    # Otherwise nothing
    if ($logman | Select-String "Error:") {
        Write-SimpleLogFile -string "[ERROR] - Problem stepping PerfWiz size:" -Name "ExPerfWiz.log"
        Write-SimpleLogFile -string $logman -Name "ExPerfWiz.log"
        throw $logman
    } else {}
}
