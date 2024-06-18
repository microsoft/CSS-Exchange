# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeContainer.ps1

function Get-ExchangeOtherWellKnownObjects {
    [CmdletBinding()]
    param ()

    $otherWellKnownObjectIds = @{
        "C262A929D691B74A9E068728F8F842EA" = "Organization Management"
        "DB72C41D49580A4DB304FE6981E56297" = "Recipient Management"
        "1A9E39D35ABE5747B979FFC0C6E5EA26" = "View-Only Organization Management"
        "45FA417B3574DC4E929BC4B059699792" = "Public Folder Management"
        "E80CDFB75697934981C898B4DBC5A0C6" = "UM Management"
        "B3DDC6BE2A3BE84B97EB2DCE9477E389" = "Help Desk"
        "BEA432C94E1D254EAF99B40573360D5B" = "Records Management"
        "C67FDE2E8339674490FBAFDCA3DFDC95" = "Discovery Management"
        "4DB8E7754EB6C1439565612E69A80A4F" = "Server Management"
        "D1281926D1F55B44866D1D6B5BD87A09" = "Delegated Setup"
        "03B709F451F3BF4388E33495369B6771" = "Hygiene Management"
        "B30A449BA9B420458C4BB22F33C52766" = "Compliance Management"
        "A7D2016C83F003458132789EEB127B84" = "Exchange Servers"
        "EA876A58DB6DD04C9006939818F800EB" = "Exchange Trusted Subsystem"
        "02522ECF9985984A9232056FC704CC8B" = "Managed Availability Servers"
        "4C17D0117EBE6642AFAEE03BC66D381F" = "Exchange Windows Permissions"
        "9C5B963F67F14A4B936CB8EFB19C4784" = "ExchangeLegacyInterop"
        "776B176BD3CB2A4DA7829EA963693013" = "Security Reader"
        "03D7F0316EF4B3498AC434B6E16F09D9" = "Security Administrator"
        "A2A4102E6F676141A2C4AB50F3C102D5" = "PublicFolderMailboxes"
    }

    $exchangeContainer = Get-ExchangeContainer
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($exchangeContainer, "(objectClass=*)", @("otherWellKnownObjects", "distinguishedName"))
    $result = $searcher.FindOne()
    foreach ($val in $result.Properties["otherWellKnownObjects"]) {
        $matchResults = $val | Select-String "^B:32:([^:]+):(.*)$"
        if ($matchResults.Matches.Groups.Count -ne 3) {
            # Only output the raw value of a corrupted entry
            [PSCustomObject]@{
                WellKnownName     = $null
                WellKnownGuid     = $null
                DistinguishedName = $null
                RawValue          = $val
            }

            continue
        }

        $wkGuid = $matchResults.Matches.Groups[1].Value
        $wkName = $otherWellKnownObjectIds[$wkGuid]

        [PSCustomObject]@{
            WellKnownName     = $wkName
            WellKnownGuid     = $wkGuid
            DistinguishedName = $matchResults.Matches.Groups[2].Value
            RawValue          = $val
        }
    }
}
