# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
TODO List
- Verify the PassWhatIf is needed.
- Provide detail description of process and docs
- Add in Write-Process logic
- Try to use json file instead of xml for restore process
- Determine log logic

#>

<#
.DESCRIPTION
    Execute the configuration actions on the remote server. This is the script block to be sent to the server.

    InputObject
        [string]FilePath
        [object[]]Actions
            [string]SelectNodesFilter
            [string]OperationType     AcceptedValues: RemoveNode, SetAttribute, AppendAttribute, MoveNode, ReplaceAttributeValue
            [object]Operation
                    Type = SetAttribute
                        [string]AttributeName
                        [string]Value
                    Type = AppendAttribute
                        [string]AttributeName
                        [string]Value
                    Type = ReplaceAttributeValue
                        [string]AttributeName
                        [string]Value
                        [string]ReplaceValue
                    Type = MoveNode
                        [string]MoveToSelectNodesFilter

                        # This is only required if the SelectNodesFilter doesn't contain a narrow filtered request where only 1 node is returned.
                        [string]ParentNodeAttributeNameFilterAdd
        [string]BackupFileName
        [object]Restore
            [string]FileName
            [bool]PassedWhatIf ?? need this?
#>
function Invoke-XmlConfigurationRemoteAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )
    begin {

        function TestLastChildNodeRestoreAction {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)]
                [string]$LastChildNode,

                [Parameter(Mandatory)]
                [string]$AttributeName,

                [Parameter(Mandatory)]
                [string]$CurrentValue,

                [Parameter(Mandatory)]
                [string]$NewValue,

                [Parameter(Mandatory)]
                [ref]$RestoreAction
            )

            # If the Current SelectNodesFilter that we are using to track down the Node contains a filter for an exact match for the attribute that we are manipulating
            # We need to properly process the change for the restore process to work.
            $splitResults = $LastChildNode.Split("[").Split("]")

            if ($splitResults -contains "@$AttributeName='$CurrentValue'" -or
                $splitResults -contains "@$AttributeName=`"$CurrentValue`"") {
                if ($LastChildNode.IndexOf($CurrentValue) -ne $LastChildNode.LastIndexOf($CurrentValue)) {
                    throw "Last child node contains multiple entries for the current value. Unable to determine new filter to use on restore."
                }

                $updatedReplaceChildNode = $LastChildNode.Replace($CurrentValue, $NewValue)
                $RestoreAction.Value.SelectNodesFilter = $RestoreAction.Value.SelectNodesFilter.Replace($LastChildNode, $updatedReplaceChildNode)
                Write-Verbose "Updated SelectNodesFilter to: $($RestoreAction.Value.SelectNodesFilter)"
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $isRestoreOption = $null -ne $InputObject.Restore
        $errorContext = New-Object System.Collections.Generic.List[object]
        $restoreActions = New-Object System.Collections.Generic.List[object]
        $originalContent = New-Object System.Collections.Generic.List[object]
        $allActionsPerformed = $true
        $gatheredAllRestoreActions = $true
        $saveRawContent = $false
        $restoreActionsSaved = $isRestoreOption -eq $true
        $alreadySaveRestoreActions = $null
        $backupRestoreFilePath = [string]::Empty
        $validationFailed = $false
        $rootSavePath = [System.IO.Path]::GetDirectoryName($InputObject.FilePath)
        $restoreFileName = "XmlConfigurationRestoreCmdlets-{0}.xml"

        if ($isRestoreOption) {
            $fileName = $restoreFileName -f $InputObject.Restore.FileName
            $backupRestoreFilePath = [System.IO.Path]::Combine($rootSavePath, $fileName)
        } elseif (-not ([string]::IsNullOrEmpty($InputObject.BackupFileName))) {
            $fileName = $restoreFileName -f $InputObject.BackupFileName
            $backupRestoreFilePath = [System.IO.Path]::Combine($rootSavePath, $fileName)
        }
    }
    process {
        <#
            Restore Xml Structure
            [object[]]OriginalContent
                [int]Id
                [object]Content
            [object[]]Actions
                [string]RestoreType             AcceptedValues: AppendChild, SetAttribute, MoveNode
                [string]SelectNodesFilter       This should always be the location where we want to handle actions in the main configuration file.
                [object]Operation
                    Type = AppendChild
                        [int]ContentId
                        [string]OriginalSelectNodesFilter
                    Type = SetAttribute
                        [string]AttributeName
                        [string]RestoreValue
                    Type = MoveNode
                        [string]MoveToSelectNodesFilter
        #>
        try {
            Write-Verbose "-------------------------------------------------"
            Write-Verbose "Starting Xml Configuration$(if($isRestoreOption){ " Restore" }) Action: $([DateTime]::Now)"
            Write-Verbose "-------------------------------------------------"

            # Verify all the actions to make sure they are valid.
            foreach ($action in $InputObject.Actions) {
                try {
                    if ([string]::IsNullOrEmpty($action.SelectNodesFilter)) {
                        throw "Failed to provide action SelectNodesFilter value."
                    }

                    if ($null -eq $action.OperationType -or
                        ($action.OperationType -ne "RemoveNode" -and
                        $action.OperationType -ne "SetAttribute" -and
                        $action.OperationType -ne "AppendAttribute" -and
                        $action.OperationType -ne "ReplaceAttributeValue" -and
                        $action.OperationType -ne "MoveNode")) {
                        throw "Failed to provide valid action OperationType."
                    }

                    if (($null -eq $action.Operation -and $action.OperationType -ne "RemoveNode") -or
                    (($action.OperationType -eq "SetAttribute" -or
                            $action.OperationType -eq "AppendAttribute") -and
                        ([string]::IsNullOrEmpty($action.Operation.AttributeName) -or
                        [string]::IsNullOrEmpty($action.Operation.Value))) -or
                    ($action.OperationType -eq "ReplaceAttributeValue" -and
                    ([string]::IsNullOrEmpty($action.Operation.AttributeName) -or
                        [string]::IsNullOrEmpty($action.Operation.Value) -or
                        $null -eq $action.Operation.ReplaceValue)) -or
                    ($action.OperationType -eq "MoveNode" -and
                        ([string]::IsNullOrEmpty($action.Operation.MoveToSelectNodesFilter)))) {
                        throw "Failed to provide correct Operation values for OperationType '$($action.OperationType)'"
                    }
                } catch {
                    Write-Verbose "Failed to provide valid Actions object structure. Inner Exception: $_"
                    $errorContext.Add($_)
                    $validationFailed = $true
                }
            }

            if (-not (Test-Path $InputObject.FilePath)) {
                $validationFailed = $true
                Write-Verbose "Incorrect FilePath provided. '$($InputObject.FilePath)'"
                $errorContext.Add((New-Object -TypeName System.IO.FileNotFoundException -ArgumentList "Configuration File Path Not Found: '$($InputObject.FilePath)'"))
            }

            if (-not $isRestoreOption -and [string]::IsNullOrEmpty($InputObject.BackupFileName)) {
                $validationFailed = $true
                Write-Verbose "BackupFileName was not set."
                $errorContext.Add((New-Object -TypeName System.Exception -ArgumentList "BackupFileName not set on input object."))
            }

            if ($validationFailed) { return }

            try {
                $contentRaw = Get-Content $InputObject.FilePath -ErrorAction Stop -Raw
                [xml]$contentXml = $contentRaw
            } catch {
                Write-Verbose "Failed to load the configuration file. Inner Exception: $_"
                $errorContext.Add($_)
                return
            }

            # attempt to load the current backup file if it exists
            if (-not ([string]::IsNullOrEmpty($backupRestoreFilePath))) {
                if ((Test-Path $backupRestoreFilePath)) {
                    Write-Verbose "Backup/Restore file already exists. Attempting to load it."

                    try {
                        $alreadySaveRestoreActions = Import-Clixml $backupRestoreFilePath -ErrorAction Stop

                        # Should really look to see if there are multiple matches already.
                        Write-Verbose "Adding pre-saved restore actions to memory"
                        foreach ($value in $alreadySaveRestoreActions.Actions) {
                            Write-Verbose "RestoreType: $($value.RestoreType) SelectNodesFilter: $($value.SelectNodesFilter)"
                            $restoreActions.Add($value)
                        }

                        Write-Verbose "Loading previous configuration files"
                        foreach ($content in $alreadySaveRestoreActions.OriginalContent) {
                            Write-Verbose "Loading Content ID $($content.Id)"
                            $originalContent.Add($content)
                        }
                    } catch {
                        Write-Verbose "Failed to load the current backup file '$backupRestoreFilePath'."
                        $errorContext.Add($_)
                        throw "Failed to load the current backup file. Inner Exception: $_"
                    }
                } else {
                    Write-Verbose "No Backup/Restore file exists at: '$($backupRestoreFilePath)'"

                    if ($isRestoreOption) {
                        Write-Error "Unable to restore due to no restore file. '$backupRestoreFilePath'"
                        # Must throw to break out and prevent from moving forward
                        throw "No restore file exists: '$($backupRestoreFilePath)'"
                    }
                }
            }

            if ($isRestoreOption) {
                # Don't need to worry about if the restore file wasn't there. This was already handled
                Write-Verbose "Starting Restore Process"
                $restoreActions.Reverse() # Reverse the order to make sure that the restore process should always work, unless manually modifying the files to where we can't find the nodes.
                foreach ($action in $restoreActions) {
                    try {
                        Write-Verbose "Trying to find nodes based off filter: '$($action.SelectNodesFilter)'"
                        $selectNodes = $contentXml.SelectNodes($action.SelectNodesFilter)
                        Write-Verbose "Found $($selectNodes.Count) node(s)"

                        if ($selectNodes.Count -eq 0) {
                            Write-Verbose "No nodes were found with the current filter. Unable to perform restore action. Filter: $($action.SelectNodesFilter)"
                            # TODO: Determine how to handle
                            continue
                        }

                        if ($selectNodes.Count -gt 1) {
                            throw "Multiple nodes found in restore process for filter '$($action.SelectNodesFilter)'. Unable to continue."
                        } else {
                            $selectNode = $selectNodes[0] # This is required to be able to do AppendChild
                        }

                        if ($action.RestoreType -eq "AppendChild") {
                            # This restore type we have to find the node to restore from the saved configuration content.
                            Write-Verbose "Attempting to find the original content by Id $($action.Operation.ContentId)"
                            $content = ($originalContent | Where-Object { $_.Id -eq $action.Operation.ContentId }).Content

                            if ($null -eq $content) {
                                throw "No Restore Content Found for the AppendChild to restore."
                            }

                            # Now we need to find the node again.
                            $restoreSelectNodes = ([xml]$content).SelectNodes($action.Operation.OriginalSelectNodesFilter)

                            if ($null -eq $restoreSelectNodes) {
                                throw "Failed to find the OriginalSelectNodesFilter: '$($action.Operation.OriginalSelectNodesFilter)'"
                            }

                            # Possible multiple nodes? Need to look into this
                            foreach ($node in $restoreSelectNodes) {
                                $importNode = $contentXml.ImportNode($node, $true)
                                [void]$selectNode.AppendChild($importNode)
                            }
                        } elseif ($action.RestoreType -eq "SetAttribute") {
                            if ($null -eq $selectNode.($action.Operation.AttributeName)) {
                                throw "Attribute '$($action.Operation.AttributeName)' currently doesn't exist on node."
                            }

                            Write-Verbose "Setting attribute '$($action.Operation.AttributeName)' with value of '$($action.Operation.RestoreValue)'"
                            $selectNode.($action.Operation.AttributeName) = $action.Operation.RestoreValue
                        } elseif ($action.RestoreType -eq "MoveNode") {
                            $moveToNodeLocation = $contentXml.SelectNodes($action.Operation.MoveToSelectNodesFilter)

                            if ($moveToNodeLocation.Count -eq 0) {
                                throw "Failed to find node selection to move to"
                            }

                            if ($moveToNodeLocation.Count -gt 1) {
                                throw "Found multiple node locations to move to. This is unsupported."
                            }

                            [void]$selectNode.ParentNode.RemoveChild($selectNode)
                            [void]$moveToNodeLocation.AppendChild($selectNode)
                        }
                    } catch {
                        $allActionsPerformed = $false
                        Write-Verbose "Failed to restore a setting. Inner Exception: $_"
                        $errorContext.Add($_)
                    }
                }

                if ($errorContext.Count -gt 0) {
                    Write-Warning "Errors occurred preventing the restore from completing."
                    return
                }

                try {
                    # Now try to save out the file
                    $contentXml.Save($InputObject.FilePath)
                } catch {
                    $allActionsPerformed = $false
                    Write-Verbose "Failed to save configuration file. Inner exception: $_"
                    $errorContext.Add($_)
                    return
                }

                try {
                    Remove-Item $backupRestoreFilePath -Force -ErrorAction Stop
                    Write-Verbose "Successfully removed the restore file."
                } catch {
                    $allActionsPerformed = $false
                    Write-Verbose "Failed to remove the restore file. Inner Exception: $_"
                    $errorContext.Add($_)
                    return
                }

                return
            }

            # for each action provided, do the action.
            foreach ($action in $InputObject.Actions) {
                Write-Verbose "Trying to find SelectNodes based off filter: '$($action.SelectNodesFilter)'"
                $selectNodes = $contentXml.SelectNodes($action.SelectNodesFilter)

                if ($selectNodes.Count -eq 0) {
                    # This shouldn't be treated as an error.
                    Write-Verbose "No nodes were found with the current filter. This could be the action was already taken or doesn't exist."
                    continue
                }

                <#
                    It is ideal to always narrow down your filter so only 1 item is returned.
                    This is going to be a requirement if the Action is to set anything other than RemoveNode.
                    However, if the calculated parent node select filter would return multiple nodes, then we will also throw an issue.
                    This is to prevent any issues with the restore process and making sure that only the correct setting gets added back to the correct location.
                #>
                Write-Verbose "Found $($selectNodes.Count) Node(s)"

                if ($selectNodes.Count -gt 1 -and
                    $action.OperationType -ne "RemoveNode") {
                    throw "Multiple Nodes found with filter '$($action.SelectNodesFilter)'. This breaks the restore logic and are unable to continue."
                }

                foreach ($node in $selectNodes) {

                    try {

                        $currentRestoreAction = [PSCustomObject]@{
                            RestoreType       = "NotSet"
                            SelectNodesFilter = [string]::Empty
                            Operation         = $null
                        }

                        if ($action.OperationType -eq "RemoveNode") {

                            $lastIndexOf = $action.SelectNodesFilter.LastIndexOf("/")

                            if ($lastIndexOf -eq -1) {
                                throw "Failed to provide a filter that would have a parent node to restore to."
                            }

                            $parentSelectNodesFilter = $action.SelectNodesFilter.Substring(0, $lastIndexOf)
                            $testSelectNodesResults = $contentXml.SelectNodes($parentSelectNodesFilter)

                            if ($testSelectNodesResults.Count -eq 0) {
                                throw "No parent nodes where found. This shouldn't occur. Unable to continue."
                            }

                            if ($testSelectNodesResults.Count -gt 1) {
                                throw "Multiple nodes returned for parent node which will result in restore process failure. Unable to continue."
                            }

                            Write-Verbose "Parent Select Nodes Filter Passed: $($parentSelectNodesFilter)"
                            $currentRestoreAction.RestoreType = "AppendChild"
                            $currentRestoreAction.SelectNodesFilter = $parentSelectNodesFilter
                            $currentRestoreAction.Operation = [PSCustomObject]@{
                                ContentId                 = $originalContent.Count
                                OriginalSelectNodesFilter = $action.SelectNodesFilter
                            }
                            # Need to handle What if scenario here
                            [void]$node.ParentNode.RemoveChild($node)
                            Write-Verbose "Successfully removed node."
                        } elseif ($action.OperationType -eq "MoveNode") {
                            $lastChildNode = $action.SelectNodesFilter.Substring($action.SelectNodesFilter.LastIndexOf("/"))
                            $moveToNodeLocation = $contentXml.SelectNodes($action.Operation.MoveToSelectNodesFilter)

                            if ($moveToNodeLocation.Count -eq 0) {
                                throw "Failed to find node selection to move to"
                            }

                            if ($moveToNodeLocation.Count -gt 1) {
                                throw "Found multiple node locations to move to. This is unsupported."
                            }

                            if ([string]::IsNullOrEmpty($action.Operation.ParentNodeAttributeNameFilterAdd)) {
                                $moveToSelectNodesFilter = $action.SelectNodesFilter.Replace($lastChildNode, "")
                            } else {
                                $moveToSelectNodesFilter = $action.SelectNodesFilter.Replace($lastChildNode, "") +
                                "[@$($action.Operation.ParentNodeAttributeNameFilterAdd)='$($node.ParentNode.($action.Operation.ParentNodeAttributeNameFilterAdd))']"
                            }

                            $currentRestoreAction.RestoreType = "MoveNode"
                            $currentRestoreAction.SelectNodesFilter = $action.Operation.MoveToSelectNodesFilter + $lastChildNode
                            $currentRestoreAction.Operation = [PSCustomObject]@{
                                MoveToSelectNodesFilter = $moveToSelectNodesFilter
                            }

                            # Now verify that we can move it back for the restore process.
                            Write-Verbose "Verifying possible restore process with filter: $($currentRestoreAction.Operation.MoveToSelectNodesFilter)"
                            $verifyMoveBack = $contentXml.SelectNodes($currentRestoreAction.Operation.MoveToSelectNodesFilter)

                            if ($verifyMoveBack.Count -ne 1) {
                                throw "Found multiple node locations for the move back. Since we are unable to restore, preventing move from occurring."
                            }

                            [void]$node.ParentNode.RemoveChild($node)
                            [void]$moveToNodeLocation.AppendChild($node)
                        } elseif ($action.OperationType -eq "SetAttribute" -or
                            $action.OperationType -eq "AppendAttribute" -or
                            $action.OperationType -eq "ReplaceAttributeValue") {

                            if ($null -eq $node.($action.Operation.AttributeName)) {
                                throw "Attribute '$($action.Operation.AttributeName)' doesn't exist on this node"
                            }

                            $currentRestoreAction.RestoreType = "SetAttribute"
                            $currentRestoreAction.SelectNodesFilter = $action.SelectNodesFilter
                            $currentRestoreAction.Operation = [PSCustomObject]@{
                                AttributeName = $action.Operation.AttributeName
                                RestoreValue  = $node.($action.Operation.AttributeName)
                            }
                            Write-Verbose "Stored the current value of the attribute. '$($currentRestoreAction.Operation.RestoreValue)'"

                            if ($action.OperationType -eq "AppendAttribute") {
                                $currentValue = $node.($action.Operation.AttributeName)
                                # If currentValue already has what we are trying to append with, don't do anything.
                                if ($currentValue.EndsWith($action.Operation.Value)) {
                                    Write-Verbose "Already have the appended value, skipping over action"
                                    continue
                                }
                                $newAppendValue = $node.($action.Operation.AttributeName) + $action.Operation.Value
                                $params = @{
                                    LastChildNode = $action.SelectNodesFilter.Substring($action.SelectNodesFilter.LastIndexOf("/"))
                                    AttributeName = $action.Operation.AttributeName
                                    CurrentValue  = $currentValue
                                    NewValue      = $newAppendValue
                                    RestoreAction = [ref]$currentRestoreAction
                                }
                                TestLastChildNodeRestoreAction @params
                                $node.($action.Operation.AttributeName) = $newAppendValue
                            } elseif ($action.OperationType -eq "ReplaceAttributeValue") {
                                # With this operation, we need to treat this similar as AppendAttribute value with handling the restore process
                                $currentValue = $node.($action.Operation.AttributeName)
                                $newReplaceValue = $currentValue.Replace($action.Operation.Value, $action.Operation.ReplaceValue)

                                $params = @{
                                    LastChildNode = $action.SelectNodesFilter.Substring($action.SelectNodesFilter.LastIndexOf("/"))
                                    AttributeName = $action.Operation.AttributeName
                                    CurrentValue  = $currentValue
                                    NewValue      = $newReplaceValue
                                    RestoreAction = [ref]$currentRestoreAction
                                }
                                TestLastChildNodeRestoreAction @params
                                $node.($action.Operation.AttributeName) = $newReplaceValue
                            } else {
                                # Need to handle what if scenario here
                                $node.($action.Operation.AttributeName) = $action.Operation.Value
                                Write-Verbose "Successfully reset the value to '$($action.Operation.Value)'"
                            }
                        }

                        # Add Current Restore to list if needed.
                        if ($null -ne $alreadySaveRestoreActions) {
                            $matchFound = $null -ne ($restoreActions |
                                    Where-Object { $_.RestoreType -eq $currentRestoreAction.RestoreType -and
                                        $_.SelectNodesFilter -eq $currentRestoreAction.SelectNodesFilter })
                        }

                        if ($null -eq $alreadySaveRestoreActions -or $matchFound -eq $false) {
                            Write-Verbose "Adding new restore action"
                            $restoreActions.Add($currentRestoreAction)

                            # Since we are adding a new restore action, we need to check to see if the action requires you to save the original content
                            if ($currentRestoreAction.RestoreType -eq "AppendChild") {
                                $saveRawContent = $true
                            }
                        } else {
                            Write-Verbose "Found match, don't overwrite setting. Not adding to restore action"
                        }
                    } catch {
                        Write-Verbose "Ran into an exception while executing the actions. Inner Exception: $_"
                        $errorContext.Add($_)
                        # Determine if we want to break out of here.
                    }
                }
            }

            # If there has been an error, we don't want to continue.
            if ($errorContext.Count -gt 0) { return }

            try {
                if ($saveRawContent) {
                    $originalContent.Add(([PSCustomObject]@{
                                Id      = $originalContent.Count
                                Content = $contentRaw
                            }))
                }
                $restoreActionResults = [PSCustomObject]@{
                    OriginalContent = $originalContent
                    Actions         = $restoreActions
                }
                # Maybe we don't want to save if nothing new was added.
                # Save out the restore action prior to saving the configuration file.
                $restoreActionResults | Export-Clixml -Path $backupRestoreFilePath -Encoding utf8 -Force -ErrorAction Stop
                Write-Verbose "Successfully saved out the restore actions to path: $backupRestoreFilePath"
                $restoreActionsSaved = $true
            } catch {
                Write-Verbose "Unable to export Restore Actions. Inner Exception: $_"
                $errorContext.Add($_)
                return
            }

            try {
                $contentXml.Save($InputObject.FilePath)
                Write-Verbose "Successfully saved out the configuration file to path: $($InputObject.FilePath)"
            } catch {
                Write-Verbose "Failed to save the updated configuration file. Inner Exception: $_"
                $errorContext.Add($_)
            }
        } catch {
            Write-Verbose "Failed to compete Xml Configuration Execution. Inner Exception: $_"
            $errorContext.Add($_)
            return
        }
    }
    end {
        Write-Verbose "Ending Xml Configuration$(if($isRestoreOption) { " Restore"}) Action: $([DateTime]::Now)"
        Write-Verbose "-------------------------------------------------"

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
