# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-VSSWriter.ps1

function Get-VSSWritersBefore {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    Write-Host "$(Get-Date) Checking VSS Writer Status: (All Writers must be in a Stable state before running this script)"
    $writers = Get-VSSWriter
    $writers | Export-Csv $OutputPath\vssWritersBefore.csv -NoTypeInformation
    $exchangeWriter = $writers | Where-Object { $_.Name -eq "Microsoft Exchange Writer" }
    $writersInErrorState = $writers | Where-Object { $_.State -ne "[1] Stable" }

    if ($null -ne $writersInErrorState) {
        Write-Warning "WARNING: One or more writers are NOT in a 'Stable' state, STOPPING SCRIPT."
        $writersInErrorState | Format-Table Name, State | Out-Host
        exit
    }

    $writers | Sort-Object Name | Format-Table | Out-Host

    if ($null -eq $exchangeWriter) {

        #Check for possible COM security issue.
        $oleKey = "HKLM:\SOFTWARE\Microsoft\Ole"
        $dcomKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM"

        $possibleDcomPermissionIssue = ((Test-Path $oleKey) -and
            ($null -ne (Get-ItemProperty $oleKey).DefaultAccessPermission)) -or
        ((Test-Path $dcomKey) -and
            ($null -ne (Get-ItemProperty $dcomKey).MachineAccessRestriction))

        Write-Warning "WARNING: Microsoft Exchange Writer not present on server. Unable to perform proper backups on the server."

        if ($possibleDcomPermissionIssue) {
            Write-Host " - Recommend to verify local Administrators group applied to COM+ Security settings: https://aka.ms/VSSTester-COMSecurity"
        }

        Write-Host " - Recommend to restart MSExchangeRepl service to see if the writer comes back. If it doesn't, review the application logs for any events to determine why."
        Write-Host " --- Look for Event ID 2003 in the application logs to verify that all internal components come online. If you see this event, try to use PSExec.exe to start a cmd.exe as the SYSTEM account and run 'vssadmin list writers'"
        Write-Host " --- If you find the Microsoft Exchange Writer, then we have a permissions issue on the computer that is preventing normal user accounts from finding all the writers."
        Write-Host " - If still not able to determine why, need to have a Microsoft Engineer review ExTrace with Cluster.Replay tags of the MSExchangeRepl service starting up."
        Write-Host
        Write-Host "Stopping Script"
        exit
    }
}
