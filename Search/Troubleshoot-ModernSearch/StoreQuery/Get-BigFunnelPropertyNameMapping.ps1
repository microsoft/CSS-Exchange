Function Get-BigFunnelPropertyNameMapping {
    [CmdletBinding()]
    param(
        [object]$StoreQueryHandler,
        [int]$MailboxNumber
    )

    begin {
        $bigFunnelPropNameMapping = New-Object PSCustomObject
        $propMatchings = [PSCustomObject]@{
            BigFunnelCorrelationId         = "p{0:x}0048"
            BigFunnelIndexingStart         = "p{0:x}0040"
            IndexingAttemptCount           = "p{0:x}0003"
            IndexingBatchRetryAttemptCount = "p{0:x}0003"
            IndexingErrorCode              = "p{0:x}0003"
            IndexingErrorMessage           = "p{0:x}001F"
            ErrorProperties                = "p{0:x}101F"
            ErrorTags                      = "p{0:x}101F"
            IsPartiallyIndexed             = "p{0:x}000B"
            IsPermanentFailure             = "p{0:x}000B"
            LastIndexingAttemptTime        = "p{0:x}0040"
            DetectedLanguage               = "p{0:x}001F"
        }
    }
    process {
        $StoreQueryHandler.ResetQueryInstances()
        $StoreQueryHandler.SetSelect(@(
                "PropName",
                "PropNumber"))

        $StoreQueryHandler.SetFrom("ExtendedPropertyNameMapping")

        $StoreQueryHandler.SetWhere("MailboxNumber = $MailboxNumber and PropGuid = '0B63E350-9CCC-11D0-BCDB-00805FCCCE04'")
        $StoreQueryHandler.AddToWhere(" and (PropName = 'BigFunnelCorrelationId' or PropName = 'BigFunnelIndexingStart'")
        $StoreQueryHandler.AddToWhere(" or PropName = 'IndexingAttemptCount' or PropName = 'IndexingBatchRetryAttemptCount'")
        $StoreQueryHandler.AddToWhere(" or PropName = 'IndexingErrorCode' or PropName = 'IndexingErrorMessage' or")
        $StoreQueryHandler.AddToWhere(" PropName = 'ErrorProperties' or PropName = 'ErrorTags' or PropName = 'IsPartiallyIndexed'")
        $StoreQueryHandler.AddToWhere(" or PropName = 'IsPermanentFailure' or PropName = 'LastIndexingAttemptTime' or PropName = 'DetectedLanguage')")

        $StoreQueryHandler.IsUnlimited = $true
        $result = $StoreQueryHandler.InvokeGetStoreQuery()

        for ($i = 0; $i -lt $result.Count; $i++) {
            $bigFunnelPropNameMapping | Add-Member -MemberType NoteProperty -Name ($result.PropName[$i]) -Value (
                $propMatchings."$($result.PropName[$i])" -f $result.PropNumber[$i]
            )
        }
    }
    end {
        return $bigFunnelPropNameMapping
    }
}
