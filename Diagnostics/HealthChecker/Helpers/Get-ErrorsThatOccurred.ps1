# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ErrorsThatOccurred {

    function WriteErrorInformation {
        [CmdletBinding()]
        param(
            [object]$CurrentError
        )
        Write-VerboseErrorInformation $CurrentError
        Write-Verbose "-----------------------------------`r`n`r`n"
    }

    if ($Error.Count -gt 0) {
        Write-Grey(" "); Write-Grey(" ")
        function Write-Errors {
            Write-Verbose "`r`n`r`nErrors that occurred that wasn't handled"

            Get-UnhandledErrors | ForEach-Object {
                Write-Verbose "Error Index: $($_.Index)"
                WriteErrorInformation $_.ErrorInformation
            }

            Write-Verbose "`r`n`r`nErrors that were handled"
            Get-HandledErrors | ForEach-Object {
                Write-Verbose "Error Index: $($_.Index)"
                WriteErrorInformation $_.ErrorInformation
            }
        }

        if ((Test-UnhandledErrorsOccurred)) {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please send the HealthChecker-Debug_*.txt, HealthChecker-Errors.json, and .xml file to ExToolsFeedback@microsoft.com.")
            $Script:Logger.PreventLogCleanup = $true
            Write-Errors
            #Need to convert Error to Json because running into odd issues with trying to export $Error out in my lab. Got StackOverflowException for one of the errors i always see there.
            try {
                $Error |
                    ConvertTo-Json |
                    Out-File ("$Script:OutputFilePath\HealthChecker-Errors.json")
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
