# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Write-ResultsToScreen {
    param(
        [Hashtable]$ResultsToWrite
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $indexOrderGroupingToKey = @{}

    foreach ($keyGrouping in $ResultsToWrite.Keys) {
        $indexOrderGroupingToKey[$keyGrouping.DisplayOrder] = $keyGrouping
    }

    $sortedIndexOrderGroupingToKey = $indexOrderGroupingToKey.Keys | Sort-Object

    foreach ($key in $sortedIndexOrderGroupingToKey) {
        Write-Verbose "Working on Key: $key"
        $keyGrouping = $indexOrderGroupingToKey[$key]
        Write-Verbose "Working on Key Group: $($keyGrouping.Name)"
        Write-Verbose "Total lines to write: $($ResultsToWrite[$keyGrouping].Count)"

        try {
            if ($keyGrouping.DisplayGroupName) {
                Write-Grey($keyGrouping.Name)
                $dashes = [string]::empty
                1..($keyGrouping.Name.Length) | ForEach-Object { $dashes = $dashes + "-" }
                Write-Grey($dashes)
            }

            foreach ($line in $ResultsToWrite[$keyGrouping]) {
                try {
                    $tab = [string]::Empty

                    if ($line.TabNumber -ne 0) {
                        1..($line.TabNumber) | ForEach-Object { $tab = $tab + "`t" }
                    }

                    if ([string]::IsNullOrEmpty($line.Name)) {
                        $displayLine = $line.DisplayValue
                    } else {
                        $displayLine = [string]::Concat($line.Name, ": ", $line.DisplayValue)
                    }

                    $writeValue = "{0}{1}" -f $tab, $displayLine
                    switch ($line.WriteType) {
                        "Grey" { Write-Grey($writeValue) }
                        "Yellow" { Write-Yellow($writeValue) }
                        "Green" { Write-Green($writeValue) }
                        "Red" { Write-Red($writeValue) }
                        "OutColumns" { Write-OutColumns($line.OutColumns) }
                    }
                } catch {
                    # We do not want to call Invoke-CatchActions here because we want the issues reported.
                    Write-Verbose "Failed inside the section loop writing. Writing out a blank line and continuing. Inner Exception: $_"
                    Write-Grey ""
                }
            }

            Write-Grey ""
        } catch {
            # We do not want to call Invoke-CatchActions here because we want the issues reported.
            Write-Verbose "Failed in $($MyInvocation.MyCommand) outside section writing loop. Inner Exception: $_"
            Write-Grey ""
        }
    }
}
