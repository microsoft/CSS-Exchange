# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-CategoryOffStatistics {
    [CmdletBinding()]
    param(
        [object]$MailboxStatistics
    )
    begin {
        $categories = New-Object 'System.Collections.Generic.List[string]'
    }
    process {
        if ($MailboxStatistics.BigFunnelNotIndexedCount -ge 250) {
            $categories.Add("NotIndexed")
        }

        if ($MailboxStatistics.BigFunnelCorruptedCount -ge 100) {
            $categories.Add("Corrupted")
        }

        if ($MailboxStatistics.BigFunnelPartiallyIndexedCount -ge 1000) {
            $categories.Add("PartiallyIndexed")
        }

        if ($MailboxStatistics.BigFunnelStaleCount -ge 100) {
            $categories.Add("Stale")
        }

        if ($MailboxStatistics.BigFunnelShouldNotBeIndexedCount -ge 5000) {
            $categories.Add("ShouldNotBeIndexed")
        }
    }
    end {
        if ($categories.Count -eq 0) {
            $categories.Add("NotIndexed")
        }
        return $categories
    }
}
