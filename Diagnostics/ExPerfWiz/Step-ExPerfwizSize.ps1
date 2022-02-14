Function Step-ExPerfwizSize {
    <#

    .SYNOPSIS
    Increases the max size of the experfwiz file by 1

    .DESCRIPTION
    To work around an issue with where start-experfwiz might fail this will increament the max size by 1mb

    .PARAMETER Name
    Name of the Data Collector set

    Default Exchange_Perfwiz

    .PARAMETER Server
    Name of the server

    Default LocalHost

	.OUTPUTS
    none

    .EXAMPLE
    Increase the max size of the default local experfwiz by 1

    Step-ExperfWizSize

    .EXAMPLE
    Increase the max size of a named remote experfwiz by 1

    Step-ExPerfwizSize -Name "My Collector Set" -Server RemoteServer-01

    #>

    [cmdletbinding()]
    param (
        [string]
        $Name = "Exchange_Perfwiz",

        [string]
        $Server = $env:ComputerName
    )

    # Step up the size of the perfwiz by 1
    $perfmon = Get-ExPerfwiz -Name $Name -Server $Server
    $newSize = $perfmon.maxsize + 1

    # increment the size
    [string]$logman = $null
    [string]$logman = logman update -name $Name -s $Server -max $newSize

    # If we find an error throw
    # Otherwise nothing
    if ($logman | select-string "Error:") {      
        Write-Logfile -string "[ERROR] - Problem stepping perfwize size:"
        Write-Logfile -string $logman
        Throw $logman
    }
    else {}
}