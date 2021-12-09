# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-FolderInformation.ps1
. $PSScriptRoot\Get-MessageInformationObject.ps1
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
        $storeQueryHandler = $storeQueryHandler | ResetQueryInstances

        $addSelect = @($extPropMapping | Get-Member |
                Where-Object { $_.MemberType -eq "NoteProperty" } |
                ForEach-Object { return $extPropMapping.($_.Name) })

        $storeQueryHandler = $storeQueryHandler |
            SetSelect -Value @(
                "FolderId",
                "MessageDocumentId",
                "p0E1D001F",
                "p1035001F",
                "MessageId",
                "HasAttachments",
                "Size",
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
                "DateReceived") |
            AddToSelect -Value $addSelect |
            SetFrom -Value "Message" |
            SetWhere -Value "MailboxNumber = $($BasicMailboxQueryContext.MailboxNumber)"

        if ($null -ne $DocumentId -and
            $DocumentId -ne 0) {
            $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " and MessageDocumentId = $DocumentId"
        } else {
            if ($MatchSubjectSubstring) {
                $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " and Subject LIKE `"%$MessageSubject%`""
            } else {
                $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " and Subject = `"$MessageSubject`""
            }

            if ($null -ne $FolderInformation -and
                $FolderInformation.Count -ne 0) {

                if ($FolderInformation.Count -eq 1) {
                    $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " and FolderId = '$FolderId'"
                } else {
                    $folderFilter = ($FolderInformation.FolderId |
                            ForEach-Object {
                                "FolderId='$_'"
                            }) -join " or "
                    $storeQueryHandler = $storeQueryHandler | AddToWhere -Value " and ($folderFilter)"
                }
            }
        }

        $storeQueryHandler.IsUnlimited = $true
        [array]$messages = $storeQueryHandler | InvokeGetStoreQuery

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
                (Get-MessageInformationObject -StoreQueryMessage $messages[$i] `
                    -BigFunnelPropNameMapping $extPropMapping `
                    -DisplayName $displayName)
            )
        }
    }
    end {
        return $messageList
    }
}

