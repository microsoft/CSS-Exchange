Function Get-QueryItemResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicUserQueryContext,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]]
        $DocumentId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $QueryString,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $QueryScope
    )
    begin {
        $QueryString = $QueryString.ToLower()
        $resultList = New-Object 'System.Collections.Generic.List[object]'
    }
    process {

        $storeQueryHandler = $BasicUserQueryContext.StoreQueryHandler
        $mailboxNumber = $BasicUserQueryContext.MailboxNumber

        foreach ($docId in $DocumentId) {

            $storeQueryHandler.ResetQueryInstances()
            $storeQueryHandler.SetSelect("*")
            $storeQueryHandler.SetFrom("BigFunnelMatchFilter('$QueryString', $mailboxNumber, $docId, '$QueryScope')")
            $queryResult = $storeQueryHandler.InvokeGetStoreQuery()

            if ($queryResult.Value.Count -ne 1) {
                $filterResult = "BigFunnelMatchFilter Failed"
            } elseif ($queryResult.Value) {
                $filterResult = $true
            } else {
                $filterResult = $false
            }

            $storeQueryHandler.SetFrom("BigFunnelMatchPOI('$QueryString', $mailboxNumber, $docId, '$QueryScope')")
            $queryResult = $storeQueryHandler.InvokeGetStoreQuery()

            if ($queryResult.Value.Count -ne 1) {
                $poiResult = "BigFunnelMatchPOI Failed"
            } elseif ($queryResult.Value) {
                $poiResult = $true
            } else {
                $poiResult = $false
            }

            $resultList.Add([PSCustomObject]@{
                    DocumentID           = $docId
                    BigFunnelMatchFilter = $filterResult
                    BigFunnelMatchPOI    = $poiResult
                })
        }
    }
    end {
        return $resultList
    }
}