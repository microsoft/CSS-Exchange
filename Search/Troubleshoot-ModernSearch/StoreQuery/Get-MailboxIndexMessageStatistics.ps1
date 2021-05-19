. $PSScriptRoot\Get-IndexingErrorMessage.ps1
. $PSScriptRoot\Get-MessageInformationObject.ps1
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
                "Size",
                "HasAttachments",
                "MessageClass",
                "p0E1D001F",
                "p1035001F",
                "BigFunnelPOISize",
                "BigFunnelPOIIsUpToDate",
                "BigFunnelPoiNotNeededReason"))

        $storeQueryHandler.AddToSelect($addSelect)
        $storeQueryHandler.SetFrom("Message")
        $storeQueryHandler.SetWhere("MailboxNumber = $mailboxNumber AND FolderId != $conversationFolderId")

        switch ($Category) {
            "All" {
                #Do Nothing
            }
            "Indexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) AND (BigFunnelPOIIsUpToDate = true)")
                $storeQueryHandler.AddToWhere(" AND ($($extPropMapping.IsPartiallyIndexed) = null or $($extPropMapping.IsPartiallyIndexed) = false)")
            }
            "PartiallyIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = true)")
                $storeQueryHandler.AddToWhere(" AND $($extPropMapping.IsPartiallyIndexed) = true")
            }
            "NotIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)")
            }
            "Corrupted" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0) and (BigFunnelPOIIsUpToDate = true)")
            }
            "Stale" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)")
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)")
            }
            "ShouldNotBeIndexed" {
                $storeQueryHandler.AddToWhere(" AND (BigFunnelPoiNotNeededReason > 0)")
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

            $messageInformationObject = Get-MessageInformationObject -StoreQueryMessage $messages[$i] `
                -BigFunnelPropNameMapping $extPropMapping

            $messageInformationObject | Add-Member -MemberType NoteProperty -Name "CondensedErrorMessage" -Value (Get-IndexingErrorMessage -Message $messageInformationObject)

            $messageList.Add($messageInformationObject)
        }
    }
    end {
        return $messageList
    }
}
