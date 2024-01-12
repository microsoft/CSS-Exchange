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
        [string]BackupFileName
        [object]Restore
            [string]FileName
            [bool]PassedWhatIf
#>
function Invoke-IISConfigurationRemoteAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $isRestoreOption = $null -ne $InputObject.Restore
        $errorContext = New-Object System.Collections.Generic.List[object]
        $restoreActions = New-Object System.Collections.Generic.List[object]
        $allActionsPerformed = $true
        $gatheredAllRestoreActions = $true
        $restoreActionsSaved = $isRestoreOption -eq $true
        $progressCounter = 0
        $backupRestoreFilePath = [string]::Empty
        $loadingJson = $null
        $rootSavePath = "$($env:WINDIR)\System32\inetSrv\config\"
        $logFilePath = [System.IO.Path]::Combine($rootSavePath, "IISManagementDebugLog.txt")
        $restoreFileName = "IISManagementRestoreCmdlets-{0}.json"
        $loggingDisabled = $false

        if (-not (Test-Path $rootSavePath)) {
            try {
                New-Item -Path $rootSavePath -ItemType Directory -ErrorAction Stop
            } catch {
                Write-Verbose "Failed to create the directory for logging."
                $loggingDisabled = $true
            }
        }

        # To avoid duplicate code for log being written and keeping code in sync, just going to do the restore option here.
        # It is going to be a different property filled out on the InputObject
        if ($isRestoreOption) {
            $fileName = $restoreFileName -f $InputObject.Restore.FileName
            $backupRestoreFilePath = [System.IO.Path]::Combine($rootSavePath, $fileName)
        } else {
            $backupProgressCounter = 0
            $backupActionsCount = $InputObject.Actions.Count
            $totalActions = $InputObject.Actions.Count

            if (-not ([string]::IsNullOrEmpty($InputObject.BackupFileName))) {
                $fileName = $restoreFileName -f $InputObject.BackupFileName
                $backupRestoreFilePath = [System.IO.Path]::Combine($rootSavePath, $fileName)
            }
        }

        $remoteActionProgressParams = @{
            ParentId        = 0
            Id              = 1
            Activity        = "Executing$(if($isRestoreOption){" Restore"}) Actions on $env:ComputerName"
            Status          = [string]::Empty
            PercentComplete = 0
        }

        function Write-VerboseAndLog {
            param(
                [string]$Message
            )

            Write-Verbose $Message

            try {

                if ($loggingDisabled) { return }

                $Message | Out-File $logFilePath -Append -ErrorAction Stop
            } catch {
                # Logging shouldn't provided that configuration wasn't successful.
                # Therefore, do no add to errorContext
                Write-Verbose "Failed to log out file. Inner Exception: $_"
            }
        }

        function GetLocationValue {
            [CmdletBinding()]
            param(
                [hashtable]$CmdParameters
            )

            if ($null -ne $CmdParameters["Location"]) {
                $location = $CmdParameters["Location"]
            } else {
                $location = $CmdParameters["PSPath"]
            }
            return $location
        }
    }
    process {

        try {
            Write-VerboseAndLog "-------------------------------------------------"
            Write-VerboseAndLog "Starting IIS Configuration$(if($isRestoreOption){ " Restore" }) Action: $([DateTime]::Now)"
            Write-VerboseAndLog "-------------------------------------------------"

            # Attempt to load the restore file if it exists.
            if (-not ([string]::IsNullOrEmpty($backupRestoreFilePath))) {
                if ((Test-Path $backupRestoreFilePath)) {
                    Write-VerboseAndLog "Backup file already exists, loading the current file."

                    try {
                        $loadingJson = Get-Content $backupRestoreFilePath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

                        if ($null -ne $loadingJson) {
                            $loadingJson | ForEach-Object {
                                $hash = @{}
                                foreach ($p in $_.Parameters.PSObject.Properties) {
                                    $hash.Add($p.Name, $p.Value)
                                }

                                $restoreActions.Add([PSCustomObject]@{
                                        Cmdlet     = $_.Cmdlet
                                        Parameters = $hash
                                    })
                            }
                        }
                    } catch {
                        Write-VerboseAndLog "Failed to load the current backup file: '$backupRestoreFilePath'"
                        $errorContext.Add($_)
                        # We should rethrow here to avoid continuing on a corrupt backup file.
                        throw "Failed to load the current backup file. Inner Exception: $_"
                    }
                } else {
                    Write-VerboseAndLog "No backup file exists at: '$backupRestoreFilePath'"
                    if ($isRestoreOption) {
                        Write-Error "Unable to restore due to no restore file. '$backupRestoreFilePath'"
                        # Must throw since we need this in order to restore
                        throw "No restore file exists: $backupRestoreFilePath"
                    }
                }
            }

            if ($isRestoreOption) {

                $totalActions = $restoreActions.Count

                foreach ($cmd in $restoreActions) {
                    try {
                        $commandParameters = $cmd.Parameters
                        $location = GetLocationValue $commandParameters
                        $progressCounter++
                        $remoteActionProgressParams.Status = "Restoring settings $($commandParameters["Name"]) at '$location'"
                        $remoteActionProgressParams.PercentComplete = ($progressCounter / $totalActions * 100)
                        Write-Progress @remoteActionProgressParams

                        # force particular parameters
                        $commandParameters["ErrorAction"] = "Stop"
                        $commandParameters["WhatIf"] = [bool]($InputObject.Restore.PassedWhatIf)

                        # Manual way to create param string
                        $paramsString = [string]::Empty

                        foreach ($key in $commandParameters.Keys) {
                            $paramsString += "-$key `"$($commandParameters[$key])`" "
                        }
                        Write-VerboseAndLog "Doing restore of cmdlet: $($cmd.Cmdlet) $paramsString"

                        & $cmd.Cmdlet @commandParameters
                    } catch {
                        $allActionsPerformed = $false
                        Write-VerboseAndLog "Failed to restore a setting. Inner Exception: $_"
                        $errorContext.Add($_)
                    }
                }

                if ($allActionsPerformed) {
                    # Remove the restore file so you can't restore again.
                    try {
                        Move-Item -Path $backupRestoreFilePath -Destination ($backupRestoreFilePath.Replace(".json", ".bak")) -Force -ErrorAction Stop
                        Write-VerboseAndLog "Successfully removed the restore file."
                    } catch {
                        Write-VerboseAndLog "Failed to remove the current restore file. Inner Exception: $_"
                        $errorContext.Add($_)
                        $allActionsPerformed = $false
                    }
                } else {
                    Write-VerboseAndLog "Not removing restore file because an issue was detected with the restore."
                }

                return
            }

            if (-not ([string]::IsNullOrEmpty($backupRestoreFilePath))) {
                Write-VerboseAndLog "Attempting to get the current value of the action items to backup."
                $totalActions = $totalActions * 2 # Double to get the current value plus the setting.

                foreach ($actionItem in $InputObject.Actions) {
                    try {
                        $backupProgressCounter++
                        $progressCounter++
                        $remoteActionProgressParams.Status = "Gathering current values. $backupProgressCounter of $backupActionsCount"
                        $remoteActionProgressParams.PercentComplete = ($progressCounter / $totalActions * 100)
                        Write-Progress @remoteActionProgressParams
                        Write-VerboseAndLog "Working on '$($actionItem.Get.Cmdlet) $($actionItem.Get.ParametersToString)"
                        $params = $actionItem.Get.Parameters
                        $currentValue = & $actionItem.Get.Cmdlet @params

                        #TODO: Need to determine if this is the correct course of logic when not dealing with a true value or a Set-WebConfigProp
                        if ($null -ne $currentValue) {

                            # Some values will return a complete object. Only pull out the value.
                            if ($null -ne $currentValue.Value) {
                                $currentValue = $currentValue.Value
                            }

                            Write-VerboseAndLog "Current value set on the server: $currentValue"
                            # we want to be able to restore the original state, prior to ever running a script that does a configuration.
                            # This way if any changes were done in between executions, we will still revert back to the original state.
                            if ($null -ne $loadingJson) {
                                $parameterNames = $actionItem.Restore.Parameters.Keys | Where-Object { $_ -ne "ErrorAction" -and $_ -ne "Value" }
                                $matchCmdlet = $loadingJson | Where-Object { $_.Cmdlet -eq $actionItem.Restore.Cmdlet }

                                foreach ($restoreCmdlet in $matchCmdlet) {
                                    $index = 0
                                    $matchFound = $true

                                    while ($index -lt $parameterNames.Count) {
                                        $paramName = $parameterNames[$index]

                                        if ($null -eq $restoreCmdlet.Parameters.$paramName -or
                                            $restoreCmdlet.Parameters.$paramName -ne $actionItem.Restore.Parameters[$paramName]) {
                                            $matchFound = $false
                                            break
                                        }
                                        $index++
                                    }
                                    if ($matchFound) {
                                        Write-VerboseAndLog "Found match, don't overwrite setting."
                                        break
                                    }
                                }
                            }

                            if ($null -eq $loadingJson -or $matchFound -eq $false) {
                                Write-VerboseAndLog "Adding restore action because a match wasn't found."
                                $actionItem.Restore.Parameters.Add("Value", $currentValue)
                                $restoreActions.Add($actionItem.Restore)
                            } else {
                                Write-VerboseAndLog "Not adding restore action because it was already in the list."
                            }
                        } else {
                            #TODO: need a test case here
                            throw "NULL Current Value Address Logic"
                        }
                    } catch {
                        Write-VerboseAndLog "Failed to collect restore actions."
                        $gatheredAllRestoreActions = $false
                        $errorContext.Add($_)
                        # We don't want to continue so throw to break out.
                        throw "Failed to get the restore actions, therefore we are unable to set the configuration. Inner Exception: $_"
                    }
                }

                # Save the restore information
                try {
                    if ([string]::IsNullOrEmpty($InputObject.BackupFileName)) {
                        Write-VerboseAndLog "No Backup File Name Provided, so we aren't going to backup what we have on the server."
                    } else {
                        $restoreActions | ConvertTo-Json -ErrorAction Stop -Depth 5 | Out-File $backupRestoreFilePath -ErrorAction Stop
                        $restoreActionsSaved = $true
                        Write-VerboseAndLog "Successfully saved out restore actions."
                    }
                } catch {
                    try {
                        # Still want to support legacy OS versions just in case customers are still using that. The pretty version of ConvertTo-Json doesn't work.
                        # Need to include the compress parameter.
                        $restoreActions | ConvertTo-Json -ErrorAction Stop -Depth 5 -Compress | Out-File $backupRestoreFilePath -ErrorAction Stop
                        $restoreActionsSaved = $true
                        Write-VerboseAndLog "Successfully saved out restore actions."
                    } catch {
                        Write-VerboseAndLog "Failed to Save Out the Restore Cmdlets. Inner Exception: $_"
                        $errorContext.Add($_)
                        throw "Failed to save out the Restore Cmdlets Inner Exception: $_"
                    }
                }
            } else {
                $restoreActionsSaved = $true # TODO: Improve logic here.
            }

            # Proceed to set the configuration
            Write-VerboseAndLog "Setting the configuration actions"
            foreach ($actionItem in $InputObject.Actions.Set) {
                try {
                    $commandParameters = $actionItem.Parameters
                    $location = GetLocationValue $commandParameters
                    $progressCounter++
                    $remoteActionProgressParams.Status = "Setting $($commandParameters["Name"]) at '$location'"
                    $remoteActionProgressParams.PercentComplete = ($progressCounter / $totalActions * 100)
                    Write-Progress @remoteActionProgressParams
                    Write-VerboseAndLog "Running the following: $($actionItem.Cmdlet) $($actionItem.ParametersToString)"

                    & $actionItem.Cmdlet @commandParameters
                } catch {
                    Write-VerboseAndLog "$($env:COMPUTERNAME): Failed to set '$($commandParameters["Name"])' for '$location' with the value '$($commandParameters["Value"])'. Inner Exception $_"
                    $allActionsPerformed = $false
                    $errorContext.Add($_)
                }
            }
        } catch {
            # Catch all to make sure we return the object.
            Write-VerboseAndLog "Failed to complete remote action execution. Inner Exception: $_"
            $errorContext.Add($_)
            return
        }
    }

    end {
        try {
            Write-Progress @remoteActionProgressParams -Completed
        } catch {
            Write-VerboseAndLog "Failed to Write-Process with -Completed"
            $errorContext.Add($_)
        }

        Write-VerboseAndLog "Ending IIS Configuration$(if($isRestoreOption) { " Restore"}) Action: $([DateTime]::Now)"
        Write-VerboseAndLog "-------------------------------------------------"

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
