# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeAdSchemaClass.ps1

function Get-ExchangeAdSchemaInformation {

    process {
        Write-Verbose "Query schema class information for CVE-2021-34470 testing"
        try {
            $msExchStorageGroup = Get-ExchangeAdSchemaClass -SchemaClassName "ms-Exch-Storage-Group"
        } catch {
            Write-Verbose "Failed to run Get-ExchangeAdSchemaClass"
            Invoke-CatchActions
        }
    } end {
        return [PSCustomObject]@{
            MsExchStorageGroup = $msExchStorageGroup
        }
    }
}
