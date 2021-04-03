Function Get-MessageIndexState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicUserQueryContext,

        [Parameter(Mandatory = $true, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [string]$MessageSubject,

        [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [string]$FolderId,

        [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [switch]$MatchSubjectSubstring,

        [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
        [int]$DocumentId
    )

    begin {
        $messageList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {
        $storeQueryHandler = $BasicUserQueryContext.StoreQueryHandler
        $extPropMapping = $BasicUserQueryContext.ExtPropMapping
        $storeQueryHandler.ResetQueryInstances()

        $addSelect = @($extPropMapping | Get-Member |
                Where-Object { $_.MemberType -eq "NoteProperty" } |
                ForEach-Object { return $extPropMapping.($_.Name) })

        $storeQueryHandler.SetSelect(@(
                "FolderId",
                "MessageDocumentId",
                "MessageClass",
                "BigFunnelPOI",
                "BigFunnelPOIIsUpToDate",
                "BigFunnelPoiNotNeededReason",
                "BigFunnelPOISize",
                "BigFunnelPartialPOI",
                "BigFunnelPOIContentFlags",
                "BigFunnelMessageUncompressedPOIVersion",
                "BigFunnelL1PropertyLengths1V1",
                "BigFunnelL1PropertyLengths1V1Rebuild",
                "BigFunnelL1PropertyLengths2V1",
                "DateCreated",
                "DateReceived"))
        $storeQueryHandler.AddToSelect($addSelect)

        $storeQueryHandler.SetFrom("Message")
        $storeQueryHandler.SetWhere("MailboxNumber = $($BasicUserQueryContext.MailboxNumber)")

        if ($null -ne $DocumentId -and
            $DocumentId -ne 0) {
            $storeQueryHandler.AddToWhere(" and MessageDocumentId = $DocumentId")
        } else {

            if ($MatchSubjectSubstring) {
                $storeQueryHandler.AddToWhere(" and Subject LIKE `"%$MessageSubject%`"")
            } else {
                $storeQueryHandler.AddToWhere(" and Subject = `"$MessageSubject`"")
            }

            if (-not [string]::IsNullOrEmpty($FolderId)) {
                $storeQueryHandler.AddToWhere(" and FolderId = '$FolderId'")
            }
        }

        [array]$messages = $storeQueryHandler.InvokeGetStoreQuery()

        if ([string]::IsNullOrEmpty($messages.MessageDocumentId) -or
            $messages.Count -eq 0) {
            #No Items just return
            return
        }

        for ($i = 0; $i -lt $messages.Count; $i++) {
            $messageList.Add(
                [PSCustomObject]@{
                    FolderId                               = $messages[$i].FolderId
                    BigFunnelIndexingStart                 = $messages[$i].($extPropMapping.BigFunnelIndexingStart)
                    IndexingAttemptCount                   = $messages[$i].($extPropMapping.IndexingAttemptCount)
                    IndexingBatchRetryAttemptCount         = $messages[$i].($extPropMapping.IndexingBatchRetryAttemptCount)
                    IndexingErrorCode                      = $messages[$i].($extPropMapping.IndexingErrorCode)
                    IndexingErrorMessage                   = $messages[$i].($extPropMapping.IndexingErrorMessage)
                    ErrorProperties                        = $messages[$i].($extPropMapping.ErrorProperties)
                    ErrorTags                              = $messages[$i].($extPropMapping.ErrorTags)
                    IsPartiallyIndexed                     = $messages[$i].($extPropMapping.IsPartiallyIndexed)
                    IsPermanentFailure                     = $messages[$i].($extPropMapping.IsPermanentFailure)
                    LastIndexingAttemptTime                = $messages[$i].($extPropMapping.LastIndexingAttemptTime)
                    DetectedLanguage                       = $messages[$i].($extPropMapping.DetectedLanguage)
                    BigFunnelCorrelationId                 = $messages[$i].($extPropMapping.BigFunnelCorrelationId)
                    MessageDocumentId                      = $messages[$i].MessageDocumentId
                    MessageClass                           = $messages[$i].MessageClass
                    BigFunnelPOI                           = $messages[$i].BigFunnelPOI
                    BigFunnelPOISize                       = $messages[$i].BigFunnelPOISize
                    BigFunnelPartialPOI                    = $messages[$i].BigFunnelPartialPOI
                    BigFunnelPOIIsUpToDate                 = $messages[$i].p3655000B
                    BigFunnelPoiNotNeededReason            = $messages[$i].p365A0003
                    BigFunnelPOIContentFlags               = $messages[$i].p36630003
                    BigFunnelMessageUncompressedPOIVersion = $messages[$i].p36660003
                    BigFunnelL1PropertyLengths1V1          = $messages[$i].p3D920014
                    BigFunnelL1PropertyLengths1V1Rebuild   = $messages[$i].p3D8E0014
                    BigFunnelL1PropertyLengths2V1          = $messages[$i].p3D8D0014
                    DateCreated                            = $messages[$i].DateCreated
                    DateReceived                           = $messages[$i].DateReceived
                })
        }
    }
    end {
        return $messageList
    }
}