function Get-ExchangeVersion {
    Get-Date
    Write-Host "Verifying Exchange version..." -ForegroundColor Green $nl
    Write-Host "--------------------------------------------------------------------------------------------------------------"
    " "
    $script:exchVer = (Get-ExchangeServer $serverName).AdminDisplayVersion
    $exchVerMajor = $exchVer.major
    $exchVerMinor = $exchVer.minor

    switch ($exchVerMajor) {
        "14" {
            $script:exchVer = "2010"
        }
        "15" {
            switch ($exchVerMinor) {
                "0" {
                    $script:exchVer = "2013"
                }
                "1" {
                    $script:exchVer = "2016"
                }
                "2" {
                    $script:exchVer = "2019"
                }
            }
        }

        default {
            Write-Host "This script is only for Exchange 2010, 2013, 2016, and 2019 servers." -ForegroundColor red $nl
            do {
                Write-Host
                $continue = Read-Host "Please use the <Enter> key to exit..."
            }
            While ($null -notmatch $continue)
            exit
        }
    }

    Write-Host "$serverName is an Exchange $exchVer server. $nl"
}
