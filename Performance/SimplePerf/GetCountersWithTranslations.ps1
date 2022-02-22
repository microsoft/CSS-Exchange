# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the same objects as Get-Counter -ListSet *, but with two additional members.
    CounterSetEnglishName is the en-US name of the CounterSet.
    CounterEnglish is the collection of counter paths in en-US.
#>
function GetCountersWithTranslations {
    $counterSets = Get-Counter -ListSet * | Sort-Object CounterSetName

    $culture = Get-Culture
    if ($culture.Name -ne "en-US") {
        $localizedNameToId = @{}
        $localizedCounters = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage").Counter
        for ($i = 0; $i -lt $localizedCounters.Count; $i += 2) {
            $localizedNameToId["$($localizedCounters[$i + 1])"] = $localizedCounters[$i]
        }

        $idToEnName = @{}
        $enCounters = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009").Counter
        for ($i = 0; $i -lt $enCounters.Count; $i += 2) {
            $idToEnName["$($enCounters[$i])"] = $enCounters[$i + 1]
        }

        $currentToEn = @{}
        foreach ($localizedName in $localizedNameToId.Keys) {
            $id = $localizedNameToId[$localizedName]
            $currentToEn[$localizedName] = $idToEnName[$id]
        }

        foreach ($set in $counterSets) {
            $enSetName = $currentToEn[$set.CounterSetName]
            $set | Add-Member -MemberType NoteProperty -Name "CounterSetEnglishName" -Value $enSetName
            $enCounters = New-Object System.Collections.ArrayList
            foreach ($counter in $set.Counter) {
                $secondSlashPos = $counter.IndexOf("\", 1)
                [void]$enCounters.Add("\" + $enSetName + $(if ($set.CounterSetType -eq "MultiInstance") { "(*)" } else { "" }) + "\" + $currentToEn[$counter.Substring($secondSlashPos + 1)])
            }

            $set | Add-Member -MemberType NoteProperty -Name "CounterEnglish" -Value $enCounters
        }
    } else {
        foreach ($set in $counterSets) {
            $set | Add-Member -MemberType NoteProperty -Name "CounterSetEnglishName" -Value $set.CounterSetName
            $set | Add-Member -MemberType NoteProperty -Name "CounterEnglish" -Value $set.Counter
        }
    }

    return $counterSets
}
