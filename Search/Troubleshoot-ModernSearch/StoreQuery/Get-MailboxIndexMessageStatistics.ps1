# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        $extPropMapping = $BasicMailboxQueryContext.ExtPropMapping
        $storeQueryHandler = $BasicMailboxQueryContext.StoreQueryHandler
        $mailboxNumber = $BasicMailboxQueryContext.MailboxNumber
        $messageList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $conversationResults = $storeQueryHandler |
            ResetQueryInstances |
            SetSelect -Value "FolderId" |
            SetFrom -Value "Folder" |
            SetWhere -Value "MailboxNumber = $mailboxNumber AND DisplayName = 'Conversations'" |
            InvokeGetStoreQuery

        $storeQueryHandler = $storeQueryHandler | ResetQueryInstances
        $addSelect = @($extPropMapping | Get-Member |
                Where-Object { $_.MemberType -eq "NoteProperty" } |
                ForEach-Object { return $extPropMapping.($_.Name) })

        $storeQueryHandler = $storeQueryHandler |
            SetSelect -Value @(
                "MessageId",
                "MessageDocumentId",
                "Size",
                "HasAttachments",
                "MessageClass",
                "p0E1D001F",
                "p1035001F",
                "BigFunnelPOISize",
                "BigFunnelPOIIsUpToDate",
                "BigFunnelPoiNotNeededReason") |
            AddToSelect -Value $addSelect |
            SetFrom -Value "Message" |
            SetWhere -Value "MailboxNumber = $mailboxNumber"

        if (-not ([string]::IsNullOrWhiteSpace($conversationResults.FolderId))) {
            $storeQueryHandler = $storeQueryHandler |
                AddToWhere -Value " AND FolderId != $($conversationResults.FolderId)"
        }

        switch ($Category) {
            "All" {
                #Do Nothing
            }
            "Indexed" {
                $storeQueryHandler = $storeQueryHandler |
                    AddToWhere -Value " AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOISize > 0) AND (BigFunnelPOIIsUpToDate = true)" |
                    AddToWhere -Value " AND ($($extPropMapping.IsPartiallyIndexed) = null or $($extPropMapping.IsPartiallyIndexed) = false)"
            }
            "PartiallyIndexed" {
                $storeQueryHandler = $storeQueryHandler |
                    AddToWhere -Value " AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = true)" |
                    AddToWhere -Value " AND $($extPropMapping.IsPartiallyIndexed) = true"
            }
            "NotIndexed" {
                $storeQueryHandler = $storeQueryHandler |
                    AddToWhere -Value " AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)"
            }
            "Corrupted" {
                $storeQueryHandler = $storeQueryHandler |
                    AddToWhere -Value " AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOISize = NULL or BigFunnelPOISize <= 0) and (BigFunnelPOIIsUpToDate = true)"
            }
            "Stale" {
                $storeQueryHandler = $storeQueryHandler |
                    AddToWhere -Value " AND (BigFunnelPoiNotNeededReason = NULL or BigFunnelPoiNotNeededReason <= 0)" |
                    AddToWhere -Value " AND (BigFunnelPOISize > 0) and (BigFunnelPOIIsUpToDate = NULL or BigFunnelPOIIsUpToDate = false)"
            }
            "ShouldNotBeIndexed" {
                $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " AND (BigFunnelPoiNotNeededReason > 0)"
            }
        }

        $storeQueryHandler.IsUnlimited = $true
        [array]$messages = $storeQueryHandler | InvokeGetStoreQuery

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
