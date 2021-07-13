# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ExchangeAdSchemaClass {
    param(
        [Parameter(Mandatory = $true)][string]$SchemaClassName
    )

    Write-VerboseOutput("Calling: Get-ExchangeAdSchemaClass to query {0} schema class" -f $SchemaClassName)

    $rootDSE = [ADSI]("LDAP://RootDSE")

    if ([string]::IsNullOrEmpty($rootDSE.schemaNamingContext)) {
        return $null
    }

    $directorySearcher = New-Object System.DirectoryServices.DirectorySearcher
    $directorySearcher.SearchScope = "Subtree"
    $directorySearcher.SearchRoot = [ADSI]("LDAP://" + $rootDSE.schemaNamingContext.ToString())
    $directorySearcher.Filter = "(Name={0})" -f $SchemaClassName

    $findAll = $directorySearcher.FindAll()

    Write-VerboseOutput("Exiting: Get-ExchangeAdSchemaClass")
    return $findAll
}
