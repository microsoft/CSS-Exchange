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
    $exchVer = (Get-ExchangeServer $ServerName).AdminDisplayVersion
    $exchVerMajor = $exchVer.major
    $exchVerMinor = $exchVer.minor

    switch ($exchVerMajor) {
        "14" {
            $exchVer = "2010"
        }
        "15" {
            switch ($exchVerMinor) {
                "0" {
                    $exchVer = "2013"
                }
                "1" {
                    $exchVer = "2016"
                }
                "2" {
                    $exchVer = "2019"
                }
            }
        }

        default {
            Write-Host "  This script is only for Exchange 2013, 2016, and 2019 servers."
            exit
        }
    }

    Write-Host "  $ServerName is an Exchange $exchVer server."

    if ($exchVer -eq "2010") {
        Write-Host "  This script no longer supports Exchange 2010."
        exit
    }
}
