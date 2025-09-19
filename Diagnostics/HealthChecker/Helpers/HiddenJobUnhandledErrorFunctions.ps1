# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    These functions are related for how a remote job will pass back any unhandled errors.
#>
function Test-HiddenJobUnhandledErrors {
    $null -ne $Script:HiddenJobUnhandedErrors -and $Script:HiddenJobUnhandedErrors.Count -gt 0
}

function Invoke-WriteHiddenJobUnhandledErrors {
    if (-not (Test-HiddenJobUnhandledErrors)) {
        return
    }

    $Script:HiddenJobUnhandedErrors | ForEach-Object { WriteRemoteErrorInformation $_ }
}

<#
    Write out the Remote Error Information that we have collected.
#>
function WriteRemoteErrorInformation {
    [CmdletBinding()]
    param(
        [object]$CurrentError
    )

    [string]$errorInformation = [System.Environment]::NewLine + [System.Environment]::NewLine +
    "----------------Remote Error Information----------------" + [System.Environment]::NewLine

    if ($null -ne $CurrentError.Exception) {
        $errorInformation += "Exception Message: $($CurrentError.Exception.Message)$([System.Environment]::NewLine)"

        if ($null -ne $CurrentError.Exception.InnerException) {
            $errorInformation += "Exception Inner Exception: $($CurrentError.Exception.InnerException)$([System.Environment]::NewLine)"
        }
    }

    if ($null -ne $CurrentError.InvocationInfo.PositionMessage) {
        $errorInformation += "Position Message: $($CurrentError.InvocationInfo.PositionMessage)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorCategory_Activity))) {
        $errorInformation += "Error Category Activity: $($CurrentError.ErrorCategory_Activity)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorCategory_Reason))) {
        $errorInformation += "Error Category Reason: $($CurrentError.ErrorCategory_Reason)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorCategory_TargetName))) {
        $errorInformation += "Error Category TargetName: $($CurrentError.ErrorCategory_TargetName)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorCategory_TargetType))) {
        $errorInformation += "Error Category TargetType: $($CurrentError.ErrorCategory_TargetType)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorCategory_Message))) {
        $errorInformation += "Error Category Message: $($CurrentError.ErrorCategory_Message)$([System.Environment]::NewLine)"
    }

    if (-not ([string]::IsNullOrEmpty($CurrentError.ErrorDetails_ScriptStackTrace))) {
        $errorInformation += "Error Details Script Stack Trace: $($CurrentError.ErrorDetails_ScriptStackTrace)$([System.Environment]::NewLine)"
    }

    $errorInformation += "--------------------------------------------------------$([System.Environment]::NewLine)$([System.Environment]::NewLine)"

    Write-Verbose $errorInformation
}

<#
    Determines if the remote job had any unhandled errors that we want to have bubbled up.
    It adds the errors to the $Script:HiddenJobUnhandedErrors variable to be stored until we want to write out the information.
#>
function Invoke-HiddenJobUnhandledErrors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$RemoteJob
    )
    begin {
        if ($null -eq $Script:HiddenJobUnhandedErrors) {
            $Script:HiddenJobUnhandedErrors = @()
        }
    }
    process {
        foreach ($job in $RemoteJob) {
            if (-not $job.RemoteJob -and $null -ne $job.RemoteJob) {
                Write-Verbose "Not running a Remote Job, skipping"
            } elseif ($null -eq $job.AllErrors -and $null -ne $job.JobHandledErrors) {
                Write-Error "All Errors were not saved on this job. $($job.RunspaceId)" -ErrorAction SilentlyContinue
            } elseif ($null -ne $job.AllErrors -and $null -eq $job.JobHandledErrors) {
                $job.AllErrors |
                    ForEach-Object {
                        $Script:HiddenJobUnhandedErrors += $_
                    }
            } elseif ($null -ne $job.AllErrors -and $job.AllErrors.Count -ne $job.JobHandledErrors.Count) {
                $job.AllErrors |
                    ForEach-Object {
                        $currentError = $_
                        $handledError = $job.JobHandledErrors | Where-Object { $_.Equals($currentError) }

                        if ($null -eq $handledError) {
                            $Script:HiddenJobUnhandedErrors += $currentError
                        }
                    }
            }
        }
    }
}
