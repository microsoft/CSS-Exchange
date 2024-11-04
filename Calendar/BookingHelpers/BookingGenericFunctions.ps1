# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function SplitDomainFromEmail {
    param([string] $Email)
    return [string]$Email.Split("@")[1]
}

function SplitIdentityFromEmail {
    param([string] $Email)
    return [string]$Email.Split("@")[0]
}

function IsConsumerMailbox {
    param([string]$Identity)

    try {
        $ConsumerMb = Get-ConsumerMailbox  $Identity -ErrorAction Ignore
        return [boolean]$ConsumerMb.IsProsumerConsumerMailbox -or $ConsumerMb.IsMigratedConsumerMailbox -or $ConsumerMb.IsPremiumConsumerMailbox
    } catch {
        return $false #consumer mailbox throws error if domain mailbox
    }
}

function CheckEXOConnection {
    if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
        Write-Host "Validated connection to Exchange Online..." -ForegroundColor Green
    } else {
        Write-Error "Get-Mailbox cmdlet not found. Please validate that you are running this script from an Exchange Management Shell and try again."
        Write-Host "Look at Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline."
        exit
    }
}

function WriteTestResult {
    param(
        [string]$Title,
        [System.Boolean]$Success,
        [string]$ErrorMessage,
        [bool]$WriteMessageAlways = $false
    )
    Write-Host  ($Title.PadRight($script:PadCharsMessage) + " : ") -NoNewline
    if ($Success) {
        if ($WriteMessageAlways) {
            WriteGreenCheck
            Write-Host (" (" + $ErrorMessage + " )") -ForegroundColor Yellow
        } else {
            WriteGreenCheck -NewLine
        }
    } else {
        WriteRedX
        Write-Host (" (" + $ErrorMessage + " )") -ForegroundColor Red
    }
}

function WriteGreenCheck {
    param (
        [parameter()]
        [switch]$NewLine
    )
    $GreenCheck = @{
        Object          = [Char]8730
        ForegroundColor = 'Green'
        NoNewLine       = if ($NewLine.IsPresent) { $false } else { $true }
    }
    Write-Host @greenCheck
}

function WriteRedX {
    param (
        [parameter()]
        [switch]$NewLine
    )

    $RedX = @{
        Object          = [Char]10060
        ForegroundColor = 'Red'
        NoNewLine       = if ($NewLine.IsPresent) { $false } else { $true }
    }
    Write-Host @redX
}

function Convert-ArrayToMultilineString {
    param (
        [Array]$Array2D
    )

    # Initialize an empty string
    $OutputString = ""

    # Loop through each row (key-value pair) of the array
    foreach ($Pair in $Array2D) {
        # Ensure the array has exactly two elements (key and value)
        if ($Pair.Count -eq 2) {
            # Append the key and value to the output string in "key: value" format
            $OutputString += "$($Pair[0]): $($Pair[1])`n"
        } else {
            Write-Warning "Array row does not have exactly 2 elements: $Pair"
        }
    }

    # Return the multi-line string
    return $OutputString.TrimEnd("`n")
}
