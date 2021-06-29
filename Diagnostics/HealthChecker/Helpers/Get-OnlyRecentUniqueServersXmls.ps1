# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-OnlyRecentUniqueServersXMLs {
    param(
        [Parameter(Mandatory = $true)][array]$FileItems
    )
    $aObject = @()

    foreach ($item in $FileItems) {
        $obj = New-Object PSCustomObject
        [string]$itemName = $item.Name
        $ServerName = $itemName.Substring(($itemName.IndexOf("-") + 1), ($itemName.LastIndexOf("-") - $itemName.IndexOf("-") - 1))
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $obj | Add-Member -MemberType NoteProperty -Name FileName -Value $itemName
        $obj | Add-Member -MemberType NoteProperty -Name FileObject -Value $item
        $aObject += $obj
    }

    $grouped = $aObject | Group-Object ServerName
    $FilePathList = @()

    foreach ($gServer in $grouped) {

        if ($gServer.Count -gt 1) {
            #going to only use the most current file for this server providing that they are using the newest updated version of Health Check we only need to sort by name
            $groupData = $gServer.Group #because of win2008
            $FilePathList += ($groupData | Sort-Object FileName -Descending | Select-Object -First 1).FileObject.VersionInfo.FileName
        } else {
            $FilePathList += ($gServer.Group).FileObject.VersionInfo.FileName
        }
    }
    return $FilePathList
}
