Function Get-MessageIndexState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicMailboxQueryContext,

        [Parameter(Mandatory = $true, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [string]$MessageSubject,

        [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [object[]]$FolderInformation,

        [Parameter(Mandatory = $false, ParameterSetName = "SubjectAndFolder")]
        [ValidateNotNullOrEmpty()]
        [switch]$MatchSubjectSubstring,

        [Parameter(Mandatory = $true, ParameterSetName = "DocumentId")]
        [int]$DocumentId
    )

    begin {
        $messageList = New-Object 'System.Collections.Generic.List[object]'
        $cacheFolderNames = @{}
    }
    process {
        $storeQueryHandler = $BasicMailboxQueryContext.StoreQueryHandler
        $extPropMapping = $BasicMailboxQueryContext.ExtPropMapping
        $storeQueryHandler.ResetQueryInstances()

        $addSelect = @($extPropMapping | Get-Member |
                Where-Object { $_.MemberType -eq "NoteProperty" } |
                ForEach-Object { return $extPropMapping.($_.Name) })

        $storeQueryHandler.SetSelect(@(
                "FolderId",
                "MessageDocumentId",
                "p0E1D001F"
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
        $storeQueryHandler.SetWhere("MailboxNumber = $($BasicMailboxQueryContext.MailboxNumber)")

        if ($null -ne $DocumentId -and
            $DocumentId -ne 0) {
            $storeQueryHandler.AddToWhere(" and MessageDocumentId = $DocumentId")
        } else {

            if ($MatchSubjectSubstring) {
                $storeQueryHandler.AddToWhere(" and Subject LIKE `"%$MessageSubject%`"")
            } else {
                $storeQueryHandler.AddToWhere(" and Subject = `"$MessageSubject`"")
            }

            if ($null -ne $FolderInformation -and
                $FolderInformation.Count -ne 0) {

                if ($FolderInformation.Count -eq 1) {
                    $storeQueryHandler.AddToWhere(" and FolderId = '$FolderId'")
                } else {
                    $folderFilter = ($FolderInformation.FolderId |
                            ForEach-Object {
                                "FolderId='$_'"
                            }) -join " or "
                    $storeQueryHandler.AddToWhere(" and ($folderFilter)")
                }
            }
        }

        $storeQueryHandler.IsUnlimited = $true
        [array]$messages = $storeQueryHandler.InvokeGetStoreQuery()

        if ([string]::IsNullOrEmpty($messages.MessageDocumentId) -or
            $messages.Count -eq 0) {
            #No Items just return
            return
        }

        for ($i = 0; $i -lt $messages.Count; $i++) {
            $folderId = $messages[$i].FolderId

            $displayName = "NULL"

            if ($null -ne $FolderInformation -and
                $FolderInformation.Count -ne 0) {
                $messageFolderInfo = $FolderInformation |
                    Where-Object { $_.FolderId -eq $FolderId }

                $displayName = $messageFolderInfo.DisplayName
            } elseif (-not([string]::IsNullOrEmpty($folderId))) {

                if (-not($cacheFolderNames.ContainsKey($folderId))) {
                    $folderInformation = Get-FolderInformation -BasicMailboxQueryContext $BasicMailboxQueryContext -FolderId $folderId
                    $cacheFolderNames.Add($folderId, $folderInformation.DisplayName)
                }

                $displayName = $cacheFolderNames[$folderId]
            }

            $messageList.Add(
                [PSCustomObject]@{
                    FolderId                               = $messages[$i].FolderId
                    DisplayName                            = $displayName
                    MessageSubject                         = $messages[$i].p0E1D001F
                    IndexStatus                            = (Get-IndexStateOfMessage -Message $messages[$i] -BigFunnelPropNameMapping $extPropMapping)
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
