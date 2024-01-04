# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.DESCRIPTION
    Execute all the actions on the remote server. This is the script block that is to be sent to the server.

    InputObject
        [array]Actions
            Set
                [string]ParametersToString
                [hashtable]Parameters
                [string]Cmdlet
            Get
                [string]ParametersToString
                [hashtable]Parameters
                [string]Cmdlet
            Restore
                [string]Cmdlet
                [hashtable]Parameters
        [Nullable][int]ProgressParentId
        [string]BackupFileName
#>
function Invoke-IISConfigurationRemoteAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $restoreActions = New-Object System.Collections.Generic.List[object]
        $errorContext = New-Object System.Collections.Generic.List[object]
        $gatheredAllRestoreActions = $true
        $restoreActionsSaved = $false
        $allActionsPerformed = $true
        $backupActionsCount = $InputObject.Actions.Count
        $backupProgressCounter = 0
        $totalActions = $InputObject.Actions.Count
        $progressCounter = 0
        $remoteActionProgressParams = @{
            ParentId        = if ($null -eq $InputObject.ProgressParentId) { 1 } else { $InputObject.ProgressParentId }
            Activity        = "Executing Actions on $env:ComputerName"
            Status          = [string]::Empty
            PercentComplete = 0
        }
    }
    process {

        if (-not ([string]::IsNullOrEmpty($InputObject.BackupFileName)) -or
            $VerbosePreference) {
            # If verbose is set or if we are backing up files, we want to collect the current values. Otherwise, skip over.
            # Backup the current value that we are changing.
            Write-Verbose "Attempting to get the current value of the action items to backup."
            foreach ($actionItem in $InputObject.Actions) {

                try {
                    $backupProgressCounter++
                    $progressCounter++
                    $remoteActionProgressParams.Status = "Gathering current values. $backupProgressCounter of $backupActionsCount"
                    $remoteActionProgressParams.PercentComplete = ($progressCounter / $totalActions * 100)
                    Write-Progress @remoteActionProgressParams
                    Write-Verbose "Working on '$($actionItem.Get.Cmdlet) $($actionItem.Get.ParametersToString)"
                    $params = $actionItem.Get.Parameters
                    $currentValue = & $actionItem.Get.Cmdlet @params

                    #TODO: Need to determine if this is the correct course of logic when not dealing with a true value or a Set-WebConfigProp
                    if ($null -ne $currentValue) {
                        Write-Verbose "Current value set on the server: $currentValue"
                        $actionItem.Restore.Parameters.Add("Value", $currentValue)
                        $restoreActions.Add($actionItem.Restore)
                    } else {
                        #TODO: need a test case here
                        throw "NULL Current Value Address Logic"
                    }
                } catch {
                    Write-Verbose "Failed to collect restore actions."
                    $gatheredAllRestoreActions = $false
                    $errorContext.Add($_)
                    # We don't want to continue so throw to break out.
                    throw "Failed to get the restore actions, therefore we are unable to set the configuration. Inner Exception: $_"
                }
            }

            # Save the restore information
            try {
                # TODO Improve logic here.
                if ([string]::IsNullOrEmpty($InputObject.BackupFileName)) {
                    Write-Verbose "No Backup File Name Provided, so we aren't going to backup what we have on the server."
                } else {
                    $outFilePath = "IISManagementRestoreCmdlets-$($InputObject.BackupFileName)"
                    $outFilePath = [System.IO.Path]::Join("$($env:WINDIR)\System32\inetSrv\config\", $outFilePath)
                    $restoreActions | ConvertTo-Json -ErrorAction Stop | Out-File $outFilePath -ErrorAction Stop
                    $restoreActionsSaved = $true
                }
            } catch {
                Write-Verbose "Failed to Save Out the Restore Cmdlets. Inner Exception: $_"
            }
        } else {
            $restoreActionsSaved = $true
        }

        # Proceed to set the configuration
        foreach ($actionItem in $InputObject.Actions.Set) {
            $commandParameters = $actionItem.Parameters

            if ($null -ne $commandParameters["Location"]) {
                $location = $commandParameters["Location"]
            } else {
                $location = $commandParameters["PSPath"]
            }
            $progressCounter++
            $remoteActionProgressParams.Status = "Setting $($commandParameters["Name"]) at '$location'"
            $remoteActionProgressParams.PercentComplete = ($progressCounter / $totalActions * 100)
            Write-Progress @remoteActionProgressParams

            try {
                & $actionItem.Cmdlet @commandParameters
            } catch {
                Write-Verbose "$($env:COMPUTERNAME): Failed to set '$($commandParameters["Name"])' for '$location' with the value '$($commandParameters["Value"])'. Inner Exception $_"
                $allActionsPerformed = $false
                $errorContext.Add($_)
            }
        }
    }

    end {
        Write-Progress @remoteActionProgressParams -Completed

        return [PSCustomObject]@{
            ComputerName              = $env:COMPUTERNAME
            AllActionsPerformed       = $allActionsPerformed
            GatheredAllRestoreActions = $gatheredAllRestoreActions
            RestoreActions            = $restoreActions
            RestoreActionsSaved       = $restoreActionsSaved
            SuccessfulExecution       = $allActionsPerformed -and $gatheredAllRestoreActions -and $restoreActionsSaved -and $errorContext.Count -eq 0
            ErrorContext              = $errorContext
        }
    }
}
