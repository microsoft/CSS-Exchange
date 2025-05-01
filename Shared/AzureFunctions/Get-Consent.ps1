# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-Consent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Script needs to continue even if N was provided')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [ValidateSet("Gray", "Green", "Cyan", "Yellow", "Red")]
        [string]$Color = "Gray",

        [int]$MaxIterations = 3
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $iterationCount = 0
        $returnValue = $false
    } process {
        do {
            $iterationCount++

            Write-Host "$Message`r`n[Y] Yes [N] No: " -ForegroundColor $Color -NoNewline
            $response = Read-Host

            Write-Verbose "[$iterationCount/$MaxIterations] Input: $response"

            if ($response.Equals("y", [StringComparison]::OrdinalIgnoreCase)) {
                $returnValue = $true
                break
            } elseif ($response.Equals("n", [StringComparison]::OrdinalIgnoreCase)) {
                break
            }
        } until ($iterationCount -ge $MaxIterations)
    } end {
        return $returnValue
    }
}
