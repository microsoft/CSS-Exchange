# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-ErrorsThatOccurred {

    if ($Error.Count -gt 0) {
        Write-Grey(" "); Write-Grey(" ")
        Function Write-Errors {
            Write-Verbose "`r`n`r`nErrors that occurred that wasn't handled"

            $index = 0
            $Error |
                ForEach-Object {
                    $index++
                    $currentError = $_
                    $handledError = $Script:ErrorsExcluded |
                        Where-Object { $_.Equals($currentError) }

                        if ($null -eq $handledError) {
                            Write-Verbose "Error Index: $index"
                            Write-Verbose $currentError

                            if ($null -ne $currentError.ScriptStackTrace) {
                                Write-Verbose $currentError.ScriptStackTrace
                            }
                            Write-Verbose "-----------------------------------`r`n`r`n"
                        }
                    }

            Write-Verbose "`r`n`r`nErrors that were handled"
            $index = 0
            $Error |
                ForEach-Object {
                    $index++
                    $currentError = $_
                    $handledError = $Script:ErrorsExcluded |
                        Where-Object { $_.Equals($currentError) }

                        if ($null -ne $handledError) {
                            Write-Verbose "Error Index: $index"
                            Write-Verbose $handledError

                            if ($null -ne $handledError.ScriptStackTrace) {
                                Write-Verbose $handledError.ScriptStackTrace
                            }
                            Write-Verbose "-----------------------------------`r`n`r`n"
                        }
                    }
        }

        if ($Error.Count -ne $Script:ErrorsExcludedCount) {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please send the HealthChecker-Debug_*.txt, HealthChecker-Errors.json, and .xml file to ExToolsFeedback@microsoft.com.")
            $Script:Logger.PreventLogCleanup = $true
            Write-Errors
            #Need to convert Error to Json because running into odd issues with trying to export $Error out in my lab. Got StackOverflowException for one of the errors i always see there.
            try {
                $Error |
                    ConvertTo-Json |
                    Out-File ("$OutputFilePath\HealthChecker-Errors.json")
            } catch {
                Write-Red("Failed to export the HealthChecker-Errors.json")
                Invoke-CatchActions
            }
        } elseif ($Script:VerboseEnabled -or
            $SaveDebugLog) {
            Write-Verbose "All errors that occurred were in try catch blocks and was handled correctly."
            $Script:Logger.PreventLogCleanup = $true
            Write-Errors
        }
    } else {
        Write-Verbose "No errors occurred in the script."
    }
}
