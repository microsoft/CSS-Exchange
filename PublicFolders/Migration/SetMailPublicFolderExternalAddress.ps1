# .SYNOPSIS
# StampMailEnabledPublicFolders.ps1
#    Stamps ExternalEmailAddress property of the mail-enabled public folders with their respective EXO smtp address.
#
# .DESCRIPTION
#
# Copyright (c) 2016 Microsoft Corporation. All rights reserved.
#
# THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
# OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
#
# .PARAMETER ExecutionSummaryFile
#    The file path where operation summary will be logged.
#
# .PARAMETER Confirm
#    The Confirm switch causes the script to pause processing and requires you to acknowledge what the script will do before processing continues. You don't have to specify
#    a value with the Confirm switch.
#
# .EXAMPLE
#    .\StampMailEnabledPublicFolders.ps1 -ExecutionSummaryFile:summary.csv

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string] $ExecutionSummaryFile,

    [Parameter(Mandatory=$false)]
    [bool] $Confirm = $true
)

# Load localized strings
Import-LocalizedData -BindingVariable LocalizedStrings -FileName SetMailPublicFolderExternalAddress.strings.psd1

if (Test-Path $ExecutionSummaryFile)
{
    Remove-Item $ExecutionSummaryFile -Confirm:$false -Force
}

$logFile = New-Item -Path $ExecutionSummaryFile -ItemType File -Force -ErrorAction:Stop 

# Find EXO specific Public Folders accepted domain
Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.FindingPublicFoldersAcceptedDomain

$domain = Get-AcceptedDomain -Identity PublicFolderDestination_78c0b207_5ad2_4fee_8cb9_f373175b3f99

if ($domain -eq $null -or $domain.DomainName -eq $null -or [string]::IsNullOrWhiteSpace($domain.DomainName.ToString()))
{
    Write-Error $LocalizedStrings.MissingExoDomain
    Exit
}

$domain = $domain.DomainName.ToString().Trim()

Write-Host "[$($(Get-Date).ToString())]" ($LocalizedStrings.FoundPublicFolderAcceptedDomain -f $domain)

Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.EnumeratingMailEnabledPublicFolders

# Total mail-enabled Public Folders
$mepfs = Get-MailPublicFolder -ResultSize:Unlimited

if ($mepfs -eq $null -or $mepfs.Count -eq 0)
{
    Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.NoMailEnabledPublicFolders
    Add-Content $ExecutionSummaryFile $LocalizedStrings.NoMailEnabledPublicFolders
    Exit
}

$totalMepfs = $mepfs.Count
$mepfsRequireStamping = @()
$listOfMepfsStampedWithValidAddress = "`t"
$listOfMepfsStampedWithOtherAddress = "`t"
$listOfMepfsRequireStamping = "`t"
$totalMepfsRequireStamping = 0
$totalMepfsStampedWithValidAddress = 0
$totalMepfsStampedWithOtherAddress = 0

foreach ($mepf in $mepfs)
{
    if ($mepf.ExternalEmailAddress -eq $null -or [string]::IsNullOrWhiteSpace($mepf.ExternalEmailAddress.ToString()))
    {
        $mepfsRequireStamping += $mepf
        $listOfMepfsRequireStamping += $mepf.DisplayName + " (" + $mepf.PrimarySmtpAddress + ")`n`t"
        $totalMepfsRequireStamping++
    }
    else
    {
        $stampedSmtpAddress = $mepf.ExternalEmailAddress.ToString().ToLower()
        $primarySmtpAddress = $mepf.PrimarySmtpAddress.ToString()
        $alias = $primarySmtpAddress.Substring(0, $primarySmtpAddress.IndexOf('@'))
        $externalEmailAddress = ($alias + '@' + $domain).ToLower()
        $externalEmailAddressWithSmtpPrefix = 'smtp:' + $externalEmailAddress

        if($stampedSmtpAddress.Equals($externalEmailAddress) -or $stampedSmtpAddress.Equals($externalEmailAddressWithSmtpPrefix))
        {
            $listOfMepfsStampedWithValidAddress += $mepf.DisplayName + " (" + $mepf.PrimarySmtpAddress + ") => " + $mepf.ExternalEmailAddress + "`n`t"
            $totalMepfsStampedWithValidAddress++
        }
        else
        {
            $listOfMepfsStampedWithOtherAddress += $mepf.DisplayName + " (" + $mepf.PrimarySmtpAddress + ") => " + $mepf.ExternalEmailAddress + "`n`t"
            $totalMepfsStampedWithOtherAddress++
        }
    }
}

Write-Host "[$($(Get-Date).ToString())]" ($LocalizedStrings.EnumeratingMailEnabledPublicFoldersComplete -f $totalMepfs)

Add-Content $ExecutionSummaryFile ($LocalizedStrings.TitleForListOfMepfsRequireStamping -f $totalMepfsRequireStamping)
Add-Content $ExecutionSummaryFile $listOfMepfsRequireStamping
Add-Content $ExecutionSummaryFile ($LocalizedStrings.TitleForListOfMepfsStampedWithValidAddress -f $totalMepfsStampedWithValidAddress)
Add-Content $ExecutionSummaryFile $listOfMepfsStampedWithValidAddress
Add-Content $ExecutionSummaryFile ($LocalizedStrings.TitleForListOfMepfsStampedWithOtherAddress -f $totalMepfsStampedWithOtherAddress)
Add-Content $ExecutionSummaryFile $listOfMepfsStampedWithOtherAddress

if ($mepfsRequireStamping.Count -gt 0)
{
    if ($Confirm)
    {
        # Ask for the confirmation
        $title = $LocalizedStrings.ConfirmationTitle
        $message = ($LocalizedStrings.ConfirmationQuestion -f $totalMepfs, $totalMepfsStampedWithValidAddress, $totalMepfsStampedWithOtherAddress, $totalMepfsRequireStamping)
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription $LocalizedStrings.ConfirmationYesOption, $LocalizedStrings.ConfirmationYesOptionHelp
        $no = New-Object System.Management.Automation.Host.ChoiceDescription $LocalizedStrings.ConfirmationNoOption, $LocalizedStrings.ConfirmationNoOptionHelp

        [System.Management.Automation.Host.ChoiceDescription[]]$options = $no,$yes
        $confirmation = $host.ui.PromptForChoice($title, $message, $options, 0)

        $answer = "No"
        if ($confirmation -eq 1)
        {
            $answer = "Yes"
        }

        Add-Content $ExecutionSummaryFile ($LocalizedStrings.StampingConfirmation -f $answer)

        # Exit, if answer is "No"
        if ($confirmation -eq 0)
        {
            Write-Host "[$($(Get-Date).ToString())]" ($LocalizedStrings.ExecutionSummaryFile -f $ExecutionSummaryFile)
            Exit
        }
    }
    else
    {
        # Running with user confirmation
        Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.RunningWithConfirmation
        Add-Content $ExecutionSummaryFile $LocalizedStrings.RunningWithConfirmation
    }

    Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.StampingMailEnabledPublicFolders

    $processed = 0

    # Stamp mail-enabled public folders
    foreach ($mepf in $mepfsRequireStamping)
    {
        $primarySmtpAddress = $mepf.PrimarySmtpAddress.ToString()
        $alias = $primarySmtpAddress.Substring(0, $primarySmtpAddress.IndexOf('@'))
        $externalEmailAddress = $alias + '@' + $domain
        $mepf | Set-MailPublicFolder -ExternalEmailAddress $externalEmailAddress
        $processed++
        Write-Progress -Activity $LocalizedStrings.ProgressBarActivity -Status ($LocalizedStrings.StampedMailEnabledPublicFolders -f $processed) -PercentComplete (100*($processed/$totalMepfsRequireStamping))
    }

    Write-Host "[$($(Get-Date).ToString())]" ($LocalizedStrings.StampedMailEnabledPublicFolders -f $mepfsRequireStamping.Count)
    Add-Content $ExecutionSummaryFile ($LocalizedStrings.StampedMailEnabledPublicFolders -f $mepfsRequireStamping.Count)
}
else
{
    Write-Host "[$($(Get-Date).ToString())]" $LocalizedStrings.NoMailEnabledPublicFoldersRequiresStamping
    Add-Content $ExecutionSummaryFile $LocalizedStrings.NoMailEnabledPublicFoldersRequiresStamping
}

if ($totalMepfsStampedWithOtherAddress -gt 0)
{
    Write-Warning ($LocalizedStrings.AlreadyStampedMailEnabledPublicFolders -f $listOfMepfsStampedWithOtherAddress)
}

Write-Host "[$($(Get-Date).ToString())]" ($LocalizedStrings.ExecutionSummaryFile -f $ExecutionSummaryFile)