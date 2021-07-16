# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanData {
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    $objLogman = Get-LogmanObject -LogmanName $LogmanName -ServerName $ServerName

    if ($null -ne $objLogman) {
        switch ($objLogman.Status) {
            "Running" {
                Write-ScriptHost -WriteString ("Looks like logman {0} is running...." -f $LogmanName)
                Write-ScriptHost -WriteString ("Going to stop {0} to prevent corruption...." -f $LogmanName)
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-ScriptHost -WriteString ("Starting Logman {0} again for you...." -f $LogmanName)
                Start-Logman -LogmanName $LogmanName -ServerName $ServerName
                Write-ScriptHost -WriteString ("Done starting Logman {0} for you" -f $LogmanName)
                break
            }
            "Stopped" {
                Write-ScriptHost -WriteString ("Doesn't look like Logman {0} is running, so not going to stop it..." -f $LogmanName)
                Copy-LogmanData -ObjLogman $objLogman
                break
            }
            Default {
                Write-ScriptHost -WriteString  ("Don't know what the status of Logman '{0}' is in" -f $LogmanName)
                Write-ScriptHost -WriteString  ("This is the status: {0}" -f $objLogman.Status)
                Write-ScriptHost -WriteString ("Going to try stop it just in case...")
                Stop-Logman -LogmanName $LogmanName -ServerName $ServerName
                Copy-LogmanData -ObjLogman $objLogman
                Write-ScriptHost -WriteString ("Not going to start it back up again....")
                Write-ScriptHost -WriteString ("Please start this logman '{0}' if you need to...." -f $LogmanName) -ForegroundColor "Yellow"
                break
            }
        }
    } else {
        Write-ScriptHost -WriteString ("Can't find {0} on {1} ..... Moving on." -f $LogmanName, $ServerName)
    }
}
