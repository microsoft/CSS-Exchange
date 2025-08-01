# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ErrorMonitorFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptDebugFunctions.ps1
function Get-ErrorsThatOccurred {

    function WriteErrorInformation {
        [CmdletBinding()]
        param(
            [object]$CurrentError
        )
        Write-VerboseErrorInformation $CurrentError
    }

    if ($Error.Count -gt 0 -or $Script:SaveDebugLog) {
        Write-Host ""
        Write-Host ""
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

        function Write-ScriptDebugObject {
            Write-Verbose "Writing out the script debug objects"
            try {
                #Need to convert Error to Json because running into odd issues with trying to export $Error out in my lab. Got StackOverflowException for one of the errors i always see there.
                Add-DebugObject -ObjectKeyName "ScriptErrors" -ObjectValueEntry ($Error | ConvertTo-Json)
            } catch {
                Write-Host "Failed to convert Error to Json" -ForegroundColor Red
                Invoke-CatchActions
            }
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $path = (Join-Path -Path $Script:OutputFilePath -ChildPath "HealthChecker-ScriptDebugObject.xml")
            Get-DebugObject | Export-Clixml -Encoding utf8 -Path $path
            Write-Verbose "Took $($stopWatch.Elapsed.TotalSeconds) seconds to write out ScriptDebugObject"
            Write-Host "Script Debug Object Path: $path"
        }

        if ((Test-UnhandledErrorsOccurred)) {
            Write-Red("There appears to have been some errors in the script. To assist with debugging of the script, please send the HealthChecker-Debug_*.txt, HealthChecker-ScriptDebugObject.xml, and .xml file to ExToolsFeedback@microsoft.com.")
            Write-Red "`tPlease include in the subject of the email with 'HealthChecker-$([System.Guid]::NewGuid())' to avoid duplicate email subjects being sent to us."
            $Script:Logger.PreventLogCleanup = $true
            Write-ScriptDebugObject
            Write-Errors
        } elseif ($Script:VerboseEnabled -or
            $Script:SaveDebugLog) {
            Write-Verbose "All errors that occurred were in try catch blocks and was handled correctly."
            $Script:Logger.PreventLogCleanup = $true
            Write-ScriptDebugObject
            Write-Errors
        }
    } else {
        Write-Verbose "No errors occurred in the script."
    }
}
