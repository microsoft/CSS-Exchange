# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-FolderInformation {
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
        [string[]]$FolderId
    )
    begin {
        $folderList = New-Object 'System.Collections.Generic.List[object]'
        $mailboxNumber = $BasicMailboxQueryContext.MailboxNumber
    }
    process {
        $storeQueryHandler = $BasicMailboxQueryContext.StoreQueryHandler
        $storeQueryHandler = $storeQueryHandler | ResetQueryInstances

        if (-not([string]::IsNullOrEmpty($DisplayName))) {
            $folderQuery = $storeQueryHandler |
                SetSelect -Value "FolderId" |
                SetFrom -Value "Folder" |
                SetWhere -Value "MailboxNumber = $mailboxNumber and DisplayName = '$DisplayName'" |
                InvokeGetStoreQuery

            if ([string]::IsNullOrEmpty($folderQuery.FolderId)) {
                throw "Failed to find valid folder by Display Name: $DisplayName"
            } else {
                $FolderId = $folderQuery.FolderId
            }
        }

        $folderFilter = ($FolderId |
                ForEach-Object {
                    "FolderId='$_'"
                }) -join " or "

        [array]$folderInformation = $storeQueryHandler |
            SetSelect -Value @(
                "FolderId",
                "DisplayName",
                "ParentFolderId",
                "CreationTime",
                "LastModificationTime") |
            SetFrom -Value "Folder" |
            SetWhere -Value "MailboxNumber = $mailboxNumber and ($folderFilter)" |
            InvokeGetStoreQuery

        foreach ($folder in $folderInformation) {
            $folderList.Add([PSCustomObject]@{
                    FolderId             = $folder.FolderId
                    DisplayName          = $folder.DisplayName
                    ParentFolderId       = $folder.ParentFolderId
                    CreationTime         = $folder.CreationTime
                    LastModificationTime = $folder.LastModificationTime
                })
        }
    }
    end {
        return $folderList
    }
}
