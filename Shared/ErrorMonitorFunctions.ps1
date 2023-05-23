# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Write-ErrorInformation.ps1

function Invoke-CatchActions {
    [CmdletBinding()]
    param(
        [object]$CurrentError = $Error[0]
    )
    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $script:ErrorsExcluded += $CurrentError
    Write-Verbose "Error Excluded Count: $($Script:ErrorsExcluded.Count)"
    Write-Verbose "Error Count: $($Error.Count)"
    Write-VerboseErrorInformation $CurrentError
}

function Get-UnhandledErrors {
    [CmdletBinding()]
    param ()
    $index = 0
    return $Error |
        ForEach-Object {
            $currentError = $_
            $handledError = $Script:ErrorsExcluded |
                Where-Object { $_.Equals($currentError) }

                if ($null -eq $handledError) {
                    [PSCustomObject]@{
                        ErrorInformation = $currentError
                        Index            = $index
                    }
                }
                $index++
            }
}

function Get-HandledErrors {
    [CmdletBinding()]
    param ()
    $index = 0
    return $Error |
        ForEach-Object {
            $currentError = $_
            $handledError = $Script:ErrorsExcluded |
                Where-Object { $_.Equals($currentError) }

                if ($null -ne $handledError) {
                    [PSCustomObject]@{
                        ErrorInformation = $currentError
                        Index            = $index
                    }
                }
                $index++
            }
}

function Test-UnhandledErrorsOccurred {
    return $Error.Count -ne $Script:ErrorsExcluded.Count
}

function Invoke-ErrorCatchActionLoopFromIndex {
    [CmdletBinding()]
    param(
        [int]$StartIndex
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    Write-Verbose "Start Index: $StartIndex Error Count: $($Error.Count)"

    if ($StartIndex -ne $Error.Count) {
        # Write the errors out in reverse in the order that they came in.
        $index = $Error.Count - $StartIndex - 1
        do {
            Invoke-CatchActions $Error[$index]
            $index--
        } while ($index -ge 0)
    }
}

function Invoke-ErrorMonitoring {
    # Always clear out the errors
    # setup variable to monitor errors that occurred
    $Error.Clear()
    $Script:ErrorsExcluded = @()
}

function Invoke-WriteDebugErrorsThatOccurred {

    function WriteErrorInformation {
        [CmdletBinding()]
        param(
            [object]$CurrentError
        )
        Write-VerboseErrorInformation $CurrentError
        Write-Verbose "-----------------------------------`r`n`r`n"
    }

    if ($Error.Count -gt 0) {
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
    } else {
        Write-Verbose "No errors occurred in the script."
    }
}
