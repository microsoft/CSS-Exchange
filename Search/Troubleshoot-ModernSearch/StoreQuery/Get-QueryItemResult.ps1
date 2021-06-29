# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-QueryItemResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$BasicMailboxQueryContext,

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

        $storeQueryHandler = $BasicMailboxQueryContext.StoreQueryHandler
        $mailboxNumber = $BasicMailboxQueryContext.MailboxNumber

        foreach ($docId in $DocumentId) {

            $queryResult = $storeQueryHandler |
                ResetQueryInstances |
                SetSelect -Value "*" |
                SetFrom -Value "BigFunnelMatchFilter('$QueryString', $mailboxNumber, $docId, '$QueryScope')" |
                InvokeGetStoreQuery

            if ($queryResult.Value.Count -ne 1) {
                $filterResult = "BigFunnelMatchFilter Failed"
            } elseif ($queryResult.Value) {
                $filterResult = $true
            } else {
                $filterResult = $false
            }

            $queryResult = $storeQueryHandler |
                SetFrom -Value "BigFunnelMatchPOI('$QueryString', $mailboxNumber, $docId, '$QueryScope')" |
                InvokeGetStoreQuery

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
