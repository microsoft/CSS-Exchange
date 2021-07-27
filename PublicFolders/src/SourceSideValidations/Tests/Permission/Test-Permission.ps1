# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-PermissionJob.ps1
. $PSScriptRoot\..\New-TestResult.ps1

function Test-Permission {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSCustomObject]
        $FolderData
    )

    begin {
        $startTime = Get-Date
    }

    process {
        $folderData.IpmSubtreeByMailbox | ForEach-Object {
            $argumentList = $FolderData.MailboxToServerMap[$_.Name], $_.Name, $_.Group
            $name = $_.Name
            $scriptBlock = ${Function:Test-BadPermissionJob}
            Add-JobQueueJob @{
                ArgumentList = $argumentList
                Name         = "$name Permissions Check"
                ScriptBlock  = $scriptBlock
            }
        }

        Wait-QueuedJob
    }

    end {
        $params = @{
            TestName       = "Permission"
            ResultType     = "Duration"
            Severity       = "Information"
            FolderIdentity = ""
            FolderEntryId  = ""
            ResultData     = ((Get-Date) - $startTime)
        }

        New-TestResult @params
    }
}
