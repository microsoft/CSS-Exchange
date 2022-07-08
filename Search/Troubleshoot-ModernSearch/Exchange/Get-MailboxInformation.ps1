# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\StoreQueryFunctions.ps1
function Get-MailboxInformation {
    [CmdletBinding()]
    param(
        [string]
        $Identity,

        [bool]
        $IsArchive,

        [bool]
        $IsPublicFolder
    )

    try {

        $storeQueryMailboxInfo = Get-StoreQueryMailboxInformation -Identity $Identity -IsArchive $IsArchive -IsPublicFolder $IsPublicFolder

        if ($storeQueryMailboxInfo.ExchangeServer.AdminDisplayVersion.ToString() -notlike "Version 15.2*") {
            throw "User isn't on an Exchange 2019 server"
        }

        return $storeQueryMailboxInfo
    } catch {
        throw "Failed to find '$Identity' information. InnerException: $($Error[0].Exception)"
    }
}
