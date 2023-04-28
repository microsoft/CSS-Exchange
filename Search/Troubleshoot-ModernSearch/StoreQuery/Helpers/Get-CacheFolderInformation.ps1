# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-FolderInformation.ps1

# Get the Folder Information from a cached object first before trying to get it from Get-StoreQuery
function Get-CacheFolderInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicMailboxQueryContext,

        [Parameter(Mandatory = $true, ParameterSetName = "DisplayName")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = "FolderId")]
        [ValidateNotNullOrEmpty()]
        [string]$FolderId
    )
    begin {

        $mailboxGuid = $BasicMailboxQueryContext.StoreQueryHandler.MailboxGuid
        $returnFolderInformation = $null

        if ($null -eq $Script:CacheFolderInformation) {
            $Script:CacheFolderInformation = @{}
        }

        if (-not ($Script:CacheFolderInformation.ContainsKey($mailboxGuid))) {
            $Script:CacheFolderInformation.Add($mailboxGuid, @{})
        }
    } process {
        if ($null -ne $FolderId) {
            if (-not ($Script:CacheFolderInformation[$mailboxGuid].ContainsKey($FolderId))) {
                $folderInformation = Get-FolderInformation -BasicMailboxQueryContext $BasicMailboxQueryContext -FolderId $FolderId
                $Script:CacheFolderInformation[$mailboxGuid].Add($FolderId, $folderInformation)
            }

            $returnFolderInformation = $Script:CacheFolderInformation[$mailboxGuid][$FolderId]
        } else {
            # Because you can have multiple Display Names the same name, must query and return all the same results.
            # Since it is possible that we don't have all the folders cached already
            $returnFolderInformation = Get-FolderInformation -BasicMailboxQueryContext $BasicMailboxQueryContext -DisplayName $DisplayName

            if ($null -ne $returnFolderInformation) {
                foreach ($folderInformation in $returnFolderInformation) {
                    if (-not ($Script:CacheFolderInformation[$mailboxGuid].ContainsKey($folderInformation.FolderId))) {
                        $Script:CacheFolderInformation[$mailboxGuid].Add($folderInformation.FolderId, $folderInformation)
                    }
                }
            }
        }
    } end {
        return $returnFolderInformation
    }
}
