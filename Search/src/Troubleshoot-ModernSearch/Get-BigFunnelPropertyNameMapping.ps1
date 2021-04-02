Function Get-BigFunnelPropertyNameMapping {
    [CmdletBinding()]
    param(
        [object]$StoreQueryHandler,
        [int]$MailboxNumber
    )

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

        $propsTable = @{}
        for ($i = 0; $i -lt $result.Count; $i++) {
            $propsTable.Add($result.PropName[$i], $result.PropNumber[$i])
        }
    }
    end {
        return [PSCustomObject]@{
            BigFunnelCorrelationId  = "p{0:x}0048" -f $propsTable.BigFunnelCorrelationId
            BigFunnelIndexingStart  = "p{0:x}0040" -f $propsTable.BigFunnelIndexingStart
            IndexingAttemptCount    = "p{0:x}0003" -f $propsTable.IndexingBatchRetryAttemptCount
            IndexingErrorCode       = "p{0:x}0003" -f $propsTable.IndexingErrorCode
            IndexingErrorMessage    = "p{0:x}001F" -f $propsTable.IndexingErrorMessage
            ErrorProperties         = "p{0:x}101F" -f $propsTable.ErrorProperties
            ErrorTags               = "p{0:x}101F" -f $propsTable.ErrorTags
            IsPartiallyIndexed      = "p{0:x}000B" -f $propsTable.IsPartiallyIndexed
            IsPermanentFailure      = "p{0:x}000B" -f $propsTable.IsPermanentFailure
            LastIndexingAttemptTime = "p{0:x}0040" -f $propsTable.LastIndexingAttemptTime
            DetectedLanguage        = "p{0:x}0003" -f $propsTable.DetectedLanguage
        }
    }
}