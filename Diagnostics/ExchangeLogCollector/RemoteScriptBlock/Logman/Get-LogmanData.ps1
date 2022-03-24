# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-LogmanObject.ps1
. $PSScriptRoot\Start-Logman.ps1
. $PSScriptRoot\Stop-Logman.ps1
. $PSScriptRoot\..\IO\Copy-LogmanData.ps1
Function Get-LogmanData {
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    $objLogman = Get-LogmanObject -LogmanName $LogmanName -ServerName $ServerName

    if ($null -ne $objLogman) {
        switch ($objLogman.Status) {
            "Running" {
                Write-Host "Looks like logman $LogmanName is running...."
                Write-Host "Going to stop $LogmanName to prevent corruption...."
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-Host "Starting Logman $LogmanName again for you...."
                Start-Logman -LogmanName $LogmanName -ServerName $ServerName
                Write-Host "Done starting Logman $LogmanName for you"
                break
            }
            "Stopped" {
                Write-Host "Doesn't look like Logman $LogmanName is running, so not going to stop it..."
                Copy-LogmanData -ObjLogman $objLogman
                break
            }
            Default {
                Write-Host "Don't know what the status of Logman '$LogmanName' is in"
                Write-Host "This is the status: $($objLogman.Status)"
                Write-Host "Going to try stop it just in case..."
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-Host "Not going to start it back up again...."
                Write-Host "Please start this logman '$LogmanName' if you need to...." -ForegroundColor "Yellow"
                break
            }
        }
    } else {
        Write-Host "Can't find $LogmanName on $ServerName ..... Moving on."
    }
}
