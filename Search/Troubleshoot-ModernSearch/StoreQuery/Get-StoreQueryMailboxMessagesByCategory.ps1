# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Helpers\Get-CacheFolderInformation.ps1
. $PSScriptRoot\Helpers\Get-IndexingErrorMessage.ps1
. $PSScriptRoot\Helpers\Get-MessageInformationObject.ps1

<#
    Query the entire mailbox for messages that are a particular category type
    From testing it seems that Get-StoreQuery has a timeout of about 170 seconds,
    therefore it is possible that this might not return all the items within the mailbox.
#>
function Get-StoreQueryMailboxMessagesByCategory {
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
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
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
                "BigFunnelPoiNotNeededReason",
                "FolderId",
                "DateCreated") |
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

            $folderId = $messages[$i].FolderId
            $displayName = "NULL"

            if ($null -ne $folderId) {
                $displayFolderInformation = Get-CacheFolderInformation -BasicMailboxQueryContext $BasicMailboxQueryContext -FolderId $folderId
                if ($null -ne $displayFolderInformation -and
                    $null -ne $displayFolderInformation.DisplayName) {
                    $displayName = $displayFolderInformation.DisplayName
                }
            }

            $params = @{
                StoreQueryMessage        = $messages[$i]
                BigFunnelPropNameMapping = $extPropMapping
                DisplayName              = $displayName
            }

            $messageInformationObject = Get-MessageInformationObject @params

            $messageInformationObject | Add-Member -MemberType NoteProperty -Name "CondensedErrorMessage" -Value (Get-IndexingErrorMessage -Message $messageInformationObject)

            $messageList.Add($messageInformationObject)
        }
    }
    end {
        Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to get the mailbox index message stats for $($messageList.count) messages"
        return $messageList
    }
}
