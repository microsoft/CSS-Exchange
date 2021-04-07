Function Get-FolderInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicUserQueryContext,

        [Parameter(Mandatory = $true, ParameterSetName = "DisplayName")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = "FolderId")]
        [ValidateNotNullOrEmpty()]
        [string[]]$FolderId
    )
    begin {
        $folderList = New-Object 'System.Collections.Generic.List[object]'
        $mailboxNumber = $BasicUserQueryContext.MailboxNumber
    }
    process {
        $storeQueryHandler = $BasicUserQueryContext.StoreQueryHandler
        $storeQueryHandler.ResetQueryInstances()

        if (-not([string]::IsNullOrEmpty($DisplayName))) {
            $storeQueryHandler.SetSelect("FolderId")
            $storeQueryHandler.SetFrom("Folder")
            $storeQueryHandler.SetWhere("MailboxNumber = $mailboxNumber and DisplayName = '$DisplayName'")
            $folderQuery = $storeQueryHandler.InvokeGetStoreQuery()

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

        $storeQueryHandler.SetSelect(@(
                "FolderId",
                "DisplayName",
                "ParentFolderId",
                "CreationTime",
                "LastModificationTime"))
        $storeQueryHandler.SetFrom("Folder")
        $storeQueryHandler.SetWhere("MailboxNumber = $mailboxNumber and ($folderFilter)")
        [array]$folderInformation = $storeQueryHandler.InvokeGetStoreQuery()

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