. $PSScriptRoot\Get-IndexStateOfMessage.ps1
Function Get-MailboxIndexMessageStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicMailboxQueryContext,

        [Parameter(Mandatory = $true)]
        [ValidateSet("All", "Indexed", "PartiallyIndexed", "NotIndexed", "Corrupted", "Stale", "ShouldNotBeIndexed")]
        [string]$Category
    )
    begin {
        $conversationFolderId = [string]::Empty
        $extPropMapping = $BasicMailboxQueryContext.ExtPropMapping
        $storeQueryHandler = $BasicMailboxQueryContext.StoreQueryHandler
        $mailboxNumber = $BasicMailboxQueryContext.MailboxNumber
        $messageList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $storeQueryHandler.ResetQueryInstances()
        $storeQueryHandler.SetSelect("FolderId")
        $storeQueryHandler.SetFrom("Folder")
        $storeQueryHandler.SetWhere("MailboxNumber = $mailboxNumber AND DisplayName = 'Conversations'")

        $conversationResults = $storeQueryHandler.InvokeGetStoreQuery()

        if ($null -ne $conversationResults.FolderId) {
            $conversationFolderId = $conversationResults.FolderId
        }

        $storeQueryHandler.ResetQueryInstances()
        $addSelect = @($extPropMapping | Get-Member |
                Where-Object { $_.MemberType -eq "NoteProperty" } |
                ForEach-Object { return $extPropMapping.($_.Name) })

        $storeQueryHandler.SetSelect(@(
                "MessageId",
                "MessageDocumentId",
                "MessageClass",
                "p0E1D001F",
                "BigFunnelPOISize",
                "BigFunnelPOIIsUpToDate",
                "BigFunnelPoiNotNeededReason"))

        $storeQueryHandler.AddToSelect($addSelect)
        $storeQueryHandler.SetFrom("Message")
        $storeQueryHandler.SetWhere("MailboxNumber = $mailboxNumber AND FolderId != $conversationFolderId")

        $messageStatus = "Unknown"

        switch ($Category) {
            "All" {
                #Do Nothing
            }
            "Indexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) AND (BigFunnelPOIIsUpToDate = true)")
                $storeQueryHandler.AddToWhere(" AND ($($extPropMapping.IsPartiallyIndexed) = null or $($extPropMapping.IsPartiallyIndexed) = false)")
                $messageStatus = "Indexed"
            }
            "PartiallyIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = true)")
                $storeQueryHandler.AddToWhere(" AND $($extPropMapping.IsPartiallyIndexed) = true")
                $messageStatus = "PartiallyIndexed"
            }
            "NotIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)")
                $messageStatus = "NotIndexed"
            }
            "Corrupted" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0) and (BigFunnelPOIIsUpToDate = true)")
                $messageStatus = "Corrupted"
            }
            "Stale" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)")
                $messageStatus = "Stale"
            }
            "ShouldNotBeIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason > 0)")
                $messageStatus = "ShouldNotBeIndexed"
            }
        }

        $storeQueryHandler.IsUnlimited = $true
        [array]$messages = $storeQueryHandler.InvokeGetStoreQuery()

        if ([string]::IsNullOrEmpty($messages.MessageDocumentId) -or
            $messages.Count -eq 0) {
            #No Items
            return
        }

        for ($i = 0; $i -lt $messages.Count; $i++) {
            $message = $messages[$i]

            if ($Category -eq "All") {
                $messageStatus = Get-IndexStateOfMessage -Message $message -BigFunnelPropNameMapping $extPropMapping
            }

            $messageList.Add(
                [PSCustomObject]@{
                    MessageId                   = $message.MessageId
                    MessageDocumentId           = $message.MessageDocumentId
                    MessageClass                = $message.MessageClass
                    Subject                     = $message.p0E1D001F
                    BigFunnelPOISize            = $message.BigFunnelPOISize
                    BigFunnelPOIIsUpToDate      = $message.p3655000B
                    BigFunnelPoiNotNeededReason = $message.p365A0003
                    IsPartiallyIndexed          = $message."$($extPropMapping.IsPartiallyIndexed)"
                    IndexingErrorCode           = $message."$($extPropMapping.IndexingErrorCode)"
                    IndexingErrorMessage        = $message."$($extPropMapping.IndexingErrorMessage)"
                    LastIndexingAttemptTime     = $message."$($extPropMapping.LastIndexingAttemptTime)"
                    IndexingAttemptCount        = $message."$($extPropMapping.IndexingAttemptCount)"
                    IsPermanentFailure          = $message."$($extPropMapping.IsPermanentFailure)"
                    MessageStatus               = $messageStatus
                })
        }
    }
    end {
        return $messageList
    }
}
