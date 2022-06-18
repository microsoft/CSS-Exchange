# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Retry-Command {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Work in progress - future adjustment')]
    param(
        [Parameter(Mandatory = $true)]
        $Params,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetry = 3
    )

    # Initial retry interval is 1 second
    $retry = 1
    do {
        try {
            return Invoke-Command @Params
            break
        } catch [Exception] {
            Write-Host ("Attempt: {0} failed on the server due to error: {1}" -f $retry, $_.Exception.Message)
        }

        # Exponentially backoff with every exception
        if ($retry -le $MaxRetry) {
            $retryInterval = [math]::Pow(2, $retry-1)
            Start-Sleep -Seconds $retryInterval
        } else {
            ErrorAction  = "Stop"
            Write-Error ("{0}" -f $_.Exception.Message)
        }
    } while ($retry++ -le $MaxRetry)
}
