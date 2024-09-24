function SplitDomainFromEmail {
    param([string] $email)
    return [string]$email.Split("@")[1]
}

function IsConsumerMailbox {
    param([string]$identity)

    try {
        $consumerMb = Get-ConsumerMailbox  $identity -ErrorAction Ignore
        return [boolean]$consumerMb.IsProsumerConsumerMailbox -or $consumerMb.IsMigratedConsumerMailbox -or $consumerMb.IsPremiumConsumerMailbox
    } catch {
        return $false #consumer mailbox throws error if domain mailbox
    }
}

function IsGetMailboxAvailable {
    if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
        Write-Host "Validated connection to Exchange Online..." -ForegroundColor Green
    } else {
        Write-Error "Get-Mailbox cmdlet not found. Please validate that you are running this script from an Exchange Management Shell and try again."
        Write-Host "Look at Import-Module ExchangeOnlineManagement and Connect-ExchangeOnline."
        exit
    }
}

function WriteTestTitle {
    param([string]$title, [System.Boolean]$Success, [string]$errorMessage, [bool]$writeMessageAlways = $false)
    Write-Host  ($title.PadRight($script:PadCharsMessage) + " : ") -NoNewline
    if ($Success) {
        if ($writeMessageAlways) {
            Write-GreenCheck
            Write-Host (" (" + $errorMessage + " )") -ForegroundColor Yellow
        } else {
            Write-GreenCheck -NewLine
        }
    } else {
        write-RedX
        Write-Host (" (" + $errorMessage + " )") -ForegroundColor Red
    }
}

function Write-GreenCheck {
    param (
        [parameter()]
        [switch]$NewLine
    )
    $greenCheck = @{
        Object          = [Char]8730
        ForegroundColor = 'Green'
        NoNewLine       = if ($NewLine.IsPresent) { $false } else { $true }
    }
    Write-Host @greenCheck
}

function Write-RedX {
    param (
        [parameter()]
        [switch]$NewLine
    )

    $redX = @{
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
    $outputString = ""

    # Loop through each row (key-value pair) of the array
    foreach ($pair in $Array2D) {
        # Ensure the array has exactly two elements (key and value)
        if ($pair.Count -eq 2) {
            # Append the key and value to the output string in "key: value" format
            $outputString += "$($pair[0]): $($pair[1])`n"
        } else {
            Write-Warning "Array row does not have exactly 2 elements: $pair"
        }
    }

    # Return the multi-line string
    return $outputString.TrimEnd("`n")
}



function CheckExcelModuleInstalled {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param ()

    if (Get-Command -Module ImportExcel) {
        Write-Host "ImportExcel module is already installed."
    } else {
        # This is slow, to the tune of ~10 seconds, but much more complete.
        # Check if ImportExcel module is installed
        $moduleInstalled = Get-Module -ListAvailable | Where-Object { $_.Name -eq 'ImportExcel' }

        if ($moduleInstalled) {
            Write-Host "ImportExcel module is already installed."
        } else {
            # Check if running with administrator rights
            $isAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if (-not $isAdministrator) {
                Write-Host "Please run the script as an administrator to install the ImportExcel module."
                exit
            }

            # Ask user if they want to install the module
            if ($PSCmdlet.ShouldProcess('ImportExcel module', 'Import')) {
                Write-Verbose "Installing ImportExcel module..."

                # Install ImportExcel module
                Install-Module -Name ImportExcel -Force -AllowClobber

                Write-Host "Done. ImportExcel module is now installed. Please re-run the script."
                exit
            }
        }
    }
}
