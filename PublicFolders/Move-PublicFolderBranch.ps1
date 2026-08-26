# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# Move-PublicFolderBranch.ps1
#   Moves the contents of folders that reside along with the given folder branch to the target public folder mailbox

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    # Folder Branch
    [Parameter(
        Mandatory=$true,
        ParameterSetName="Default",
        HelpMessage = "Please specify the folder branch to move")]
    [ValidateNotNull()]
    [string] $FolderRoot,

    # Target Mailbox
    [Parameter(
        Mandatory=$true,
        ParameterSetName="Default",
        HelpMessage = "Please specify the target public folder mailbox where the contents need to go to")]
    [ValidateNotNull()]
    [string] $TargetPublicFolderMailbox,

    # Name of the organization
    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [ValidateNotNull()]
    [string] $OrganizationName,

    [Parameter(Mandatory=$false, ParameterSetName="Default")]
    [switch] $WhatIf,

    [Parameter(Mandatory=$true, ParameterSetName="ScriptUpdateOnly")]
    [switch] $ScriptUpdateOnly,

    [Parameter(Mandatory=$false)]
    [switch] $SkipVersionCheck
)

. $PSScriptRoot\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

################ START OF DEFAULTS ################
$script:FoldersToMove = @()
$script:publicFolder = $null

$PublicFolderManagement_LocalizedStrings = ConvertFrom-StringData @'
SameMailbox = Please provide a target mailbox that is different from the source mailbox.
UnlimitedSize = Mailbox {0} has unlimited size.
FeasibilityToSplit = Checking if it is possible to split the given source mailbox
FeasibilityToMove = Checking if it is possible to move contents to the given target mailbox
FeasibilityToMerge = Checking if it is possible to merge the given source mailbox
SplitSizeInformation = Minimum percentage to split is {0} while percentage occupied by source mailbox is {1}.
ImpossibleToSplit = Public folder mailbox {0} cannot be split at this point.
ImpossibleToMove = Public folder mailbox {0} is not the right candidate to accommodate the moving contents.
ImpossibleToMerge = Public folder mailbox {0} cannot be merged at this point.
RetrieveFoldersFromSourceMailbox = Determining folders that belong to source mailbox
NotEnoughFoldersToSplit = There aren't enough folders residing in the mailbox {0} to split.
FolderUnavailableToMerge = There isn't any folder residing in the mailbox {0} to merge.
IdentifyFolders = Identifying folders that are to be moved to the target mailbox
FoldersInHierarchy = Folders in the public folder hierarchy on the source mailbox
CandidatesForSplit = Possible folder branches for splitting, with total size: {0}
SelectedForSplit = Selected folder branches for splitting
MoveFolders = Folders that will be moved as part of this request:
RemoveExistingRequest = Please remove the existing request and then continue...
IssueSplitRequest = Issuing request to split the mailbox: {0}
IssueMergeRequest = Issuing request to merge the mailbox: {0}
IssueMoveBranchRequest = Issuing request to move the public folder branch: {0}
RequestName = RequestName: {0}
SourceMailbox = SourceMailbox: {0}
TargetMailbox = TargetMailbox: {0}
RequestStatus = RequestStatus: {0}
JobStatus = Use Get-PublicFolderMoveRequest cmdlet to obtain the status of the job.
SourceStatistics = Source mailbox statistics: Mailbox: {0} MailboxSize: {1} OccupiedSize: {2} PublicFoldersOccupiedSize: {3}
TargetStatistics = Target mailbox statistics: Mailbox: {0} MailboxSize: {1} OccupiedSize: {2}
'@
################## END OF DEFAULTS ################

if ($OrganizationName -ne "") {
    $script:publicFolder = Get-PublicFolder $FolderRoot -Organization:$OrganizationName -WarningAction SilentlyContinue
} else {
    $script:publicFolder = Get-PublicFolder $FolderRoot -WarningAction SilentlyContinue
}

if ($null -eq $script:publicFolder) {
    exit
}

Write-Host
Write-Host "[$($(Get-Date).ToString())]" $PublicFolderManagement_LocalizedStrings.IdentifyFolders

if ($OrganizationName -ne "") {
    $script:publicFoldersToProcess = @(Get-PublicFolder -Identity $FolderRoot -Recurse -Organization:$OrganizationName -WarningAction SilentlyContinue -ResultSize:Unlimited | `
                Where-Object -FilterScript { $_.ContentMailboxGuid -eq $script:publicFolder.ContentMailboxGuid })
} else {
    $script:publicFoldersToProcess = @(Get-PublicFolder -Identity $FolderRoot -Recurse -WarningAction SilentlyContinue -ResultSize:Unlimited | `
                Where-Object -FilterScript { $_.ContentMailboxGuid -eq $script:publicFolder.ContentMailboxGuid })
}

# Populating the folders that will be part of the move request
$publicFoldersToProcessCount = $script:publicFoldersToProcess.Count
for ($index = 0; $index -lt $publicFoldersToProcessCount; $index++) {
    $script:FoldersToMove += $script:publicFoldersToProcess[$index].Identity.ToString()
}

Write-Host
Write-Host "[$($(Get-Date).ToString())]" $PublicFolderManagement_LocalizedStrings.MoveFolders
$script:FoldersToMove | Format-Wide -Property MapiFolderPath -Column 1

if ($WhatIf) {
    exit
}

# Checking if there are any pending request in this organization
if ($OrganizationName -ne "") {
    $anyPendingRequest = Get-PublicFolderMoveRequest -Organization:$OrganizationName
} else {
    $anyPendingRequest = Get-PublicFolderMoveRequest
}

if ($null -ne $anyPendingRequest) {
    Write-Host
    Write-Host "[$($(Get-Date).ToString())]" $PublicFolderManagement_LocalizedStrings.RemoveExistingRequest
    exit
}

# Initiating the request
Write-Host
Write-Host "[$($(Get-Date).ToString())]" ($PublicFolderManagement_LocalizedStrings.IssueMoveBranchRequest -f $($FolderRoot))
if ($OrganizationName -ne "") {
    $request = New-PublicFolderMoveRequest -Folders:$script:FoldersToMove -TargetMailbox:$TargetPublicFolderMailbox -Organization:$OrganizationName
} else {
    $request = New-PublicFolderMoveRequest -Folders:$script:FoldersToMove -TargetMailbox:$TargetPublicFolderMailbox
}

if ($null -ne $request) {
    Write-Host "[$($(Get-Date).ToString())]" ($PublicFolderManagement_LocalizedStrings.RequestName -f $($request))
    Write-Host "[$($(Get-Date).ToString())]" ($PublicFolderManagement_LocalizedStrings.SourceMailbox -f $($request.SourceMailbox))
    Write-Host "[$($(Get-Date).ToString())]" ($PublicFolderManagement_LocalizedStrings.TargetMailbox -f $($request.TargetMailbox))
    Write-Host "[$($(Get-Date).ToString())]" ($PublicFolderManagement_LocalizedStrings.RequestStatus -f $($request.Status))
    Write-Host
    Write-Host "[$($(Get-Date).ToString())]" $PublicFolderManagement_LocalizedStrings.JobStatus
}
