# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-ExchangeVersion {
    [OutputType([System.Void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ServerName
    )

    Write-Host "$(Get-Date) Verifying Exchange version..."

    # Use AdminDisplayVersion and parse it into a proper System.Version
    [string]$AdminDisplayVersion = (Get-ExchangeServer $ServerName).AdminDisplayVersion
    $split1 = $AdminDisplayVersion.Substring(($AdminDisplayVersion.IndexOf(" ")) + 1, 4).Split(".")
    $buildStart = $AdminDisplayVersion.LastIndexOf(" ") + 1
    $split2 = $AdminDisplayVersion.Substring($buildStart, ($AdminDisplayVersion.LastIndexOf(")") - $buildStart)).Split(".")
    [System.Version]$exchangeVersion = "$($split1[0]).$($split1[1]).$($split2[0]).$($split2[1])"

    if ($exchangeVersion.Major -eq 15 -and $exchangeVersion.Minor -ne 0) {
        if ($exchangeVersion.Minor -eq 1) {
            $exchVer = "2016"
        }
        else {
            # Handle everything else as 2019
            $exchVer = "2019"
        }
    }
    else {
        throw "Unsupported build of Exchange. $($exchangeVersion.ToString())"
    }

    Write-Host "  $ServerName is an Exchange $exchVer server."
}
