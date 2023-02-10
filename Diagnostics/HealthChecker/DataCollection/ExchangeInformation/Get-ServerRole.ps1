# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ServerRole {
    param(
        [Parameter(Mandatory = $true)][object]$ExchangeServerObj
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $roles = $ExchangeServerObj.ServerRole.ToString()
    Write-Verbose "Roll: $roles"
    #Need to change this to like because of Exchange 2010 with AIO with the hub role.
    if ($roles -like "Mailbox, ClientAccess*") {
        return "MultiRole"
    } elseif ($roles -eq "Mailbox") {
        return "Mailbox"
    } elseif ($roles -eq "Edge") {
        return "Edge"
    } elseif ($roles -like "*ClientAccess*") {
        return "ClientAccess"
    } else {
        return "None"
    }
}
