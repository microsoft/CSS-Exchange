Function Get-ErrorsThatOccurred {

    if ($Error.Count -gt $Script:ErrorStartCount) {
        Write-Grey(" "); Write-Grey(" ")
        Function Write-Errors {
            $index = 0
            "`r`n`r`nErrors that occurred that wasn't handled" | Out-File ($Script:OutputFullPath) -Append
            $Script:Logger.WriteToFileOnly("`r`n`r`nErrors that occurred that wasn't handled")

            while ($index -lt ($Error.Count - $Script:ErrorStartCount)) {
                #for 2008R2 can't use .Contains on an array object, need to do something else.
                $goodError = $false

                foreach ($okayErrors in $Script:ErrorsExcluded) {

                    if ($okayErrors.Equals($Error[$index])) {
                        $goodError = $true
                        break
                    }
                }

                if (!($goodError)) {
                    $Script:Logger.WriteToFileOnly($Error[$index])
                    $Error[$index] | Out-File ($Script:OutputFullPath) -Append
                }
                $index++
            }
            Write-Grey(" "); Write-Grey(" ")
            "Errors that were handled" | Out-File ($Script:OutputFullPath) -Append
            $Script:Logger.WriteToFileOnly("`r`n`r`nErrors that were handled")

            foreach ($okayErrors in $Script:ErrorsExcluded) {
                $okayErrors | Out-File ($Script:OutputFullPath) -Append
                $Script:Logger.WriteToFileOnly($okayErrors)
            }
        }

        if (($Error.Count - $Script:ErrorStartCount) -ne $Script:ErrorsExcludedCount) {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please send the HealthChecker-Debug_*.txt and .xml file to ExToolsFeedback@microsoft.com.")
            $Script:Logger.PreventLogCleanup = $true
            Write-Errors
        } elseif ($Script:VerboseEnabled -or
            $SaveDebugLog) {
            Write-VerboseOutput("All errors that occurred were in try catch blocks and was handled correctly.")
            $Script:Logger.PreventLogCleanup = $true
            Write-Errors
        }
    } else {
        Write-VerboseOutput("No errors occurred in the script.")
    }
}