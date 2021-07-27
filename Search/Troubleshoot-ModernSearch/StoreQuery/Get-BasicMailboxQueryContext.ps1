# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-BigFunnelPropertyNameMapping.ps1
Function Get-BasicMailboxQueryContext {
    [CmdletBinding()]
    param(
        [object]$StoreQueryHandler
    )

    process {
        $result = $StoreQueryHandler |
            ResetQueryInstances |
            SetSelect -Value @(
                "BigFunnelIsEnabled",
                "FastIsEnabled",
                "BigFunnelMailboxCreationVersion",
                "BigFunnelDictionaryVersion",
                "BigFunnelPostingListTableVersion",
                "BigFunnelPostingListTableChunkSize",
                "BigFunnelPostingListTargetTableVersion",
                "BigFunnelPostingListTargetTableChunkSize",
                "BigFunnelMaintainRefiners",
                "CreationTime",
                "MailboxNumber") |

            SetFrom -Value "Mailbox" |
            SetWhere -Value ("MailboxGuid = '$($StoreQueryHandler.MailboxGuid)'") |
            InvokeGetStoreQuery

        $bigFunnelPropertyNameMapping = Get-BigFunnelPropertyNameMapping -StoreQueryHandler $StoreQueryHandler -MailboxNumber $result.MailboxNumber
    }
    end {
        return [PSCustomObject]@{
            BigFunnelIsEnabled                       = $result.p6781000B
            FastIsEnabled                            = $result.p330F000B
            BigFunnelMailboxCreationVersion          = $result.p33270003
            BigFunnelDictionaryVersion               = $result.p67820003
            BigFunnelPostingListTableVersion         = $result.p3D940003
            BigFunnelPostingListTableChunkSize       = $result.p3D950003
            BigFunnelPostingListTargetTableVersion   = $result.p3D900003
            BigFunnelPostingListTargetTableChunkSize = $result.p3D910003
            BigFunnelMaintainRefiners                = $result.p333E000B
            CreationTime                             = $result.p30070040
            MailboxNumber                            = $result.MailboxNumber
            StoreQueryHandler                        = $StoreQueryHandler
            ExtPropMapping                           = $bigFunnelPropertyNameMapping
        }
    }
}
