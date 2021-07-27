# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-IndexStateOfMessage.ps1
Function Get-MessageInformationObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$StoreQueryMessage,

        [Parameter(Mandatory = $true)]
        [object]$BigFunnelPropNameMapping,

        [string]$DisplayName = [string]::Empty
    )
    begin {
        $indexStatus = Get-IndexStateOfMessage -Message $StoreQueryMessage -BigFunnelPropNameMapping $BigFunnelPropNameMapping
    }
    process {
        return [PSCustomObject]@{
            FolderId                               = $StoreQueryMessage.FolderId
            DisplayName                            = $displayName
            InternetMessageId                      = $StoreQueryMessage.p1035001F
            MessageId                              = $StoreQueryMessage.MessageId
            MessageDocumentId                      = $StoreQueryMessage.MessageDocumentId
            MessageSubject                         = $StoreQueryMessage.p0E1D001F
            MessageClass                           = $StoreQueryMessage.MessageClass
            Size                                   = $StoreQueryMessage.Size
            HasAttachments                         = $StoreQueryMessage.HasAttachments
            DetectedLanguage                       = $StoreQueryMessage."$($BigFunnelPropNameMapping.DetectedLanguage)"
            IndexStatus                            = $indexStatus
            IsPermanentFailure                     = $StoreQueryMessage."$($BigFunnelPropNameMapping.IsPermanentFailure)"
            IndexingErrorMessage                   = $StoreQueryMessage."$($BigFunnelPropNameMapping.IndexingErrorMessage)"
            IndexingErrorCode                      = $StoreQueryMessage."$($BigFunnelPropNameMapping.IndexingErrorCode)"
            IsPartiallyIndexed                     = $StoreQueryMessage."$($BigFunnelPropNameMapping.IsPartiallyIndexed)"
            ErrorTags                              = $StoreQueryMessage."$($BigFunnelPropNameMapping.ErrorTags)"
            ErrorProperties                        = $StoreQueryMessage."$($BigFunnelPropNameMapping.ErrorProperties)"
            BigFunnelIndexingStart                 = $StoreQueryMessage."$($BigFunnelPropNameMapping.BigFunnelIndexingStart)"
            LastIndexingAttemptTime                = $StoreQueryMessage."$($BigFunnelPropNameMapping.LastIndexingAttemptTime)"
            IndexingBatchRetryAttemptCount         = $StoreQueryMessage."$($BigFunnelPropNameMapping.IndexingBatchRetryAttemptCount)"
            IndexingAttemptCount                   = $StoreQueryMessage."$($BigFunnelPropNameMapping.IndexingAttemptCount)"
            BigFunnelCorrelationId                 = $StoreQueryMessage."$($BigFunnelPropNameMapping.BigFunnelCorrelationId)"
            BigFunnelPOISize                       = $StoreQueryMessage.BigFunnelPOISize
            BigFunnelPartialPOI                    = $StoreQueryMessage.BigFunnelPartialPOI
            BigFunnelPOIIsUpToDate                 = $StoreQueryMessage.p3655000B
            BigFunnelPoiNotNeededReason            = $StoreQueryMessage.p365A0003
            BigFunnelPOIContentFlags               = $StoreQueryMessage.p36630003
            BigFunnelMessageUncompressedPOIVersion = $StoreQueryMessage.p36660003
            BigFunnelL1PropertyLengths1V1          = $StoreQueryMessage.p3D920014
            BigFunnelL1PropertyLengths1V1Rebuild   = $StoreQueryMessage.p3D8E0014
            BigFunnelL1PropertyLengths2V1          = $StoreQueryMessage.p3D8D0014
            DateCreated                            = $StoreQueryMessage.DateCreated
            DateReceived                           = $StoreQueryMessage.DateReceived
        }
    }
}
