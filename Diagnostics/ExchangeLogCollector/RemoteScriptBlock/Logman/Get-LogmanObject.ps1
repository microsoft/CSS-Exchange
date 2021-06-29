# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-LogmanObject {
    param(
        [Parameter(Mandatory = $true)][string]$LogmanName,
        [Parameter(Mandatory = $true)][string]$ServerName
    )
    $rawDataResults = logman -s $ServerName $LogmanName

    if ($rawDataResults[$rawDataResults.Count - 1].Contains("Set was not found.")) {
        return $null
    } else {
        $objLogman = New-Object -TypeName psobject
        $objLogman | Add-Member -MemberType NoteProperty -Name LogmanName -Value $LogmanName
        $objLogman | Add-Member -MemberType NoteProperty -Name Status -Value (Get-LogmanStatus -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name RootPath -Value (Get-LogmanRootPath -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name StartDate -Value (Get-LogmanStartDate -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name Ext -Value (Get-LogmanExt -RawLogmanData $rawDataResults)
        $objLogman | Add-Member -MemberType NoteProperty -Name RestartLogman -Value $false
        $objLogman | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $objLogman | Add-Member -MemberType NoteProperty -Name RawData -Value $rawDataResults
        $objLogman | Add-Member -MemberType NoteProperty -Name SaveRootLocation -Value $FilePath

        return $objLogman
    }
}
