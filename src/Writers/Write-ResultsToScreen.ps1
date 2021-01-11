Function Write-ResultsToScreen {
    param(
        [Hashtable]$ResultsToWrite
    )
    Write-VerboseOutput("Calling: Write-ResultsToScreen")
    $indexOrderGroupingToKey = @{}

    foreach ($keyGrouping in $ResultsToWrite.Keys) {
        $indexOrderGroupingToKey[$keyGrouping.DisplayOrder] = $keyGrouping
    }

    $sortedIndexOrderGroupingToKey = $indexOrderGroupingToKey.Keys | Sort-Object

    foreach ($key in $sortedIndexOrderGroupingToKey) {
        Write-VerboseOutput("Working on Key: {0}" -f $key)
        $keyGrouping = $indexOrderGroupingToKey[$key]
        Write-VerboseOutput("Working on Key Group: {0}" -f $keyGrouping.Name)
        Write-VerboseOutput("Total lines to write: {0}" -f ($ResultsToWrite[$keyGrouping].Count))

        if ($keyGrouping.DisplayGroupName) {
            Write-Grey($keyGrouping.Name)
            $dashes = [string]::empty
            1..($keyGrouping.Name.Length) | ForEach-Object { $dashes = $dashes + "-" }
            Write-Grey($dashes)
        }

        foreach ($line in $ResultsToWrite[$keyGrouping]) {
            $tab = [string]::Empty

            if ($line.TabNumber -ne 0) {
                1..($line.TabNumber) | ForEach-Object { $tab = $tab + "`t" }
            }

            $writeValue = "{0}{1}" -f $tab, $line.Line
            switch ($line.WriteType) {
                "Grey" { Write-Grey($writeValue) }
                "Yellow" { Write-Yellow($writeValue) }
                "Green" { Write-Green($writeValue) }
                "Red" { Write-Red($writeValue) }
            }
        }

        Write-Grey("")
    }
}