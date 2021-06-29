# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#This is mostly code that was slapped together to get the job done.
[CmdletBinding()]
param(
    [string]$ExInstall = "C:\Program Files\Microsoft\Exchange Server\V15",
    [string]$IsoRoot = "D:\"
)

$Overrides = @{"C:\Program Files\Microsoft\Exchange Server\V15\Bin".ToLower() = "D:\Setup\ServerRoles\Common".ToLower() }

Function Get-MatchingObject {
    param(
        [object]$InstallChildObject,
        [object]$IsoChildObject
    )

    return [PSCustomObject]@{
        FileName         = $InstallChildObject.Name
        InstallDirectory = $InstallChildObject.Directory.ToString()
        ISODirectory     = $IsoChildObject.Directory.ToString()
    }
}

Function Find-BestObject {
    param(
        [object]$InstallChildObject,
        [array]$IsoFoundChildObjects
    )

    #do this first
    $addCommon = $false
    $directory = $InstallChildObject.Directory.ToString().ToLower()
    if ($directory.Contains("server\v15\bin")) {
        $addCommon = $True
    }

    $foundItem = $IsoFoundChildObjects |
        Where-Object {
            $pattern = "\\Setup\\ServerRoles\\(.+)"
            if ($addCommon) { $pattern = "\\Setup\\ServerRoles\\common\\(.+)" }
            $sls = $_.Directory.ToString().ToLower() | Select-String $pattern

            if ($null -ne $sls -and
                $directory.EndsWith($sls.Matches.Groups[1].Value)) {
                return $_
            }
        }
    if ($null -ne $foundItem -and
        $foundItem.Count -eq 1) {
        return $foundItemF
    }

    #check the hash of the file against the ISO
    $installedFileHash = (Get-FileHash $InstallChildObject.FullName).Hash
    [array]$groupHash = $IsoFoundChildObjects |
        ForEach-Object {
            Get-FileHash $_.FullName
        } |
        Group-Object Hash
    if ($groupHash.Count -eq 1) {
        return $IsoFoundChildObjects[0]
    } elseif ($groupHash.Name.Contains($installedFileHash)) {
        return Get-ChildItem ($groupHash |
                Where-Object { $_.Name -eq $installedFileHash } |
                Select-Object -First 1).Group[0].Path
    }


    #see if we have more than 1 location in Exchange
    $installedFound = $installedDlls |
        Where-Object {
            $_.Name.ToLower().Equals($InstallChildObject.Name.ToLower())
        }

    #only 1 in the install path
    Function Get-BestFromMultiIsoFound {

        $testingDirectory = $InstallChildObject.Directory.ToString().ToLower()


        if ($Overrides.ContainsKey($testingDirectory)) {

            $directoryOverrideFound = $IsoFoundChildObjects.Directory |
                Where-Object {
                    $_.ToString().ToLower().Contains($Overrides[$testingDirectory])
                }

            if ($null -ne $directoryOverrideFound) {
                $IsoFoundChildObjects = $IsoFoundChildObjects |
                    Where-Object {
                        $_.FullName.ToLower().Contains($Overrides[$testingDirectory])
                    }
            }
        }

        [array]$groupHash = $IsoFoundChildObjects |
            ForEach-Object {
                Get-FileHash $_.FullName
            } |
            Group-Object Hash
        if ($groupHash.Count -eq 1) {
            return $IsoFoundChildObjects[0]
        } else {
            Write-Debug "WTF" -Debug
            throw "diff hash values WTF"
        }
    }

    if ($installedFound.Count -eq 1) {
        #only 1 ddl in the install path matching that name. Check hash if same copy.
        return Get-BestFromMultiIsoFound
    } else {
        #Possible Language path
        $lang = $InstallChildObject.Directory.ToSTring().substring(($InstallChildObject.Directory.ToSTring().LastIndexOf("\") + 1))
        if (Test-Path "D:\$lang") {

            $itemFound = $IsoFoundChildObjects | Where-Object { $_.Directory.ToString().ToLower().EndsWith("\$lang") }

            if ($itemFound.Count -eq 1) {
                return $itemFound
            } else {
                Write-Debug "idk" -Debug
                throw "idk"
            }
        }

        [array]$groupHash = $installedFound |
            ForEach-Object {
                Get-FileHash $_.FullName
            } |
            Group-Object Hash
        if ($groupHash.Count -eq 1) {
            return Get-BestFromMultiIsoFound
        }

        Write-Debug ("add logic") -Debug
        throw "add logic"
    }
    Write-Debug("hmmm...") -Debug
}





$Script:installedDlls = Get-ChildItem -Recurse $ExInstall |
    Where-Object { $_.Name.ToLower().EndsWith(".dll") -and
        !$_.FullName.StartsWith("$ExInstall\Bin\Search\Ceres\HostController\Data\Repository\") }
$Script:isoDlls = Get-ChildItem -Recurse $IsoRoot |
    Where-Object { $_.Name.ToLower().EndsWith(".dll") }

$installedGroupDirectoryDlls = $installedDlls | Group-Object Directory
$dllMappings = New-Object 'System.Collections.Generic.List[object]'

foreach ($directory in $installedGroupDirectoryDlls) {

    foreach ($findThisItem in $directory.Group) {
        $itemFound = $isoDlls |
            Where-Object {
                $_.Name.ToLower().Equals($findThisItem.Name.ToLower())
            }
        if ($null -eq $itemFound) {
            Write-Host "Failed to find any items of $($findThisItem.Name)"
        } elseif ($itemFound.Count -gt 1) {
            $bestItem = Find-BestObject -InstallChildObject $findThisItem -IsoFoundChildObjects $itemFound
            $dllMappings.Add((Get-MatchingObject -InstallChildObject $findThisItem -IsoChildObject $bestItem))
        } else {
            $dllMappings.Add((Get-MatchingObject -InstallChildObject $findThisItem -IsoChildObject $itemFound))
        }
    }
}

$dllMappings = Import-Clixml C:\Users\Han\Desktop\mappings.xml
$mapperObject = New-Object 'System.Collections.Generic.List[object]'
$groupingsByDirectory = $dllMappings | Group-Object InstallDirectory, ISODirectory

foreach ($group in $groupingsByDirectory) {
    $paths = $group.Name.Split(",").Trim()
    $installDirectory = $paths[0].Replace("$ExInstall\", "")
    $isoDirectory = $paths[1].Replace("$IsoRoot", "")
    $currentMappings = [PSCustomObject]@{
        InstallDirectory = $installDirectory
        IsoDirectory     = $isoDirectory
        DllFileNames     = (New-Object 'System.Collections.Generic.List[object]')
    }

    foreach ($fileName in $group.Group.FileName) {
        $currentMappings.DllFileNames.Add($fileName)
    }

    $mapperObject.Add($currentMappings)
}

$groupIso = $mapperObject | Group-Object IsoDirectory | Sort-Object Count -Descending
$mappings2 = New-Object 'System.Collections.Generic.List[object]'

foreach ($isoGroupings in $groupIso) {
    $isoRoot = $isoGroupings.Name
    $greatestGroup = $isoGroupings.Group[0]

    foreach ($group in $isoGroupings.Group) {
        if ($group.DLLFileNames.Count -gt $greatestGroup.DLLFileNames.Count) {
            $greatestGroup = $group
        }
    }

    $dontCopyDlls = New-Object 'System.Collections.Generic.List[object]'
    $isoGroupings.Group |
        Where-Object { $_ -ne $greatestGroup } |
        ForEach-Object {
            $_.DllFileNames | ForEach-Object {
                if (!$greatestGroup.DLLFileNames.Contains($_)) {
                    $dontCopyDlls.Add($_)
                }
            }
        }
    #for now the rest of the locations just write down all the files that we want to copy to and where.
    $otherLocations = $isoGroupings.Group |
        Where-Object { $_ -ne $greatestGroup }
    $list = New-Object 'System.Collections.Generic.List[object]'

    $otherLocations |
        ForEach-Object {
            $list.Add(
                [PSCustomObject]@{
                    InstallDirectory = $_.InstallDirectory
                    DllFileNames     = $_.DllFileNames
                }
            )
        }
    $mappings2.Add(
        [PSCustomObject]@{
            IsoRoot        = $IsoRoot
            CopyTo         = $greatestGroup.InstallDirectory
            Except         = $dontCopyDlls
            OtherLocations = $otherLocations
        }
    )
}
