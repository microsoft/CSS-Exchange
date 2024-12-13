# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ========================
# Excel needs Scriptlets helper functions to be loaded, in order to have access to graph and install Export-Excel module.
# ========================

. $PSScriptRoot\GraphInstaller.ps1
. $PSScriptRoot\BookingGenericFunctions.ps1
. $PSScriptRoot\BookingMBHelpers.ps1
. $PSScriptRoot\BookingStaffHelpers.ps1
. $PSScriptRoot\BookingServiceHelpers.ps1
. $PSScriptRoot\BookingCustomQuestionHelpers.ps1
. $PSScriptRoot\BookingStaffLogHelper.ps1

function GetExcelParams($Path, $TabName) {

    return @{
        Path                    = $Path
        FreezeTopRow            = $true
        Verbose                 = $false
        TableStyle              = "Medium3"
        WorksheetName           = $TabName
        TableName               = $TabName
        FreezeTopRowFirstColumn = $false
        AutoFilter              = $true
        AutoNameRange           = $true
        Append                  = $true
        AutoSize                = $true
        Title                   = "Bookings Support Data Collector"
        ConditionalText         = $ConditionalFormatting
    }
}

function CheckModulesAndConnectGraph {
    Write-Host -ForegroundColor Gray "Checking Excel, Graph and bookings modules"
    CheckExcelModuleInstalled
    CheckGraphAuthModuleInstalled
    CheckGraphBookingsModuleInstalled

    $ModulesInstalled = CheckGraphModulesInstalled
    Write-Verbose "Modules installed: $ModulesInstalled"
    if ($ModulesInstalled -eq $false) {
        Write-Host -ForegroundColor Red "Graph modules are not installed. Exiting..."
        exit
    }

    Connect-MgGraph -Scopes "User.Read.All", "Bookings.Read.All" -NoWelcome
}

function ExcelWrite {
    param($Identity)

    CheckModulesAndConnectGraph

    Write-Host -ForegroundColor Green "Exporting to Excel..."

    #Compose File name formatted as: BookingsSummary_<IdentityName>_<yyyy-MM-dd>_<HHmm>.xlsx
    $IdentityName = SplitIdentityFromEmail -email $Identity
    $DateStringToFileName = (Get-Date).ToString("yyyy-MM-dd")
    $HourStringToFileName = Get-Date -Format "HHmm"
    $Path = "BookingsSummary_$($IdentityName)_$($DateStringToFileName)_$($HourStringToFileName).xlsx"
    Remove-Item -Path $Path -Force -EA Ignore

    $ExcelParamsArray = GetExcelParams -path $Path -tabName "Business"

    Write-Host "Exporting Booking Business."
    $BusinessData = GetGraphBookingBusiness -Identity $Identity
    $Excel = $BusinessData | Export-Excel @ExcelParamsArray -PassThru
    Export-Excel -ExcelPackage $Excel -WorksheetName "Business" -MoveToStart

    Write-Host "Exporting Bookings Page Settings."
    $BusinessPage = GetGraphBookingBusinessPage -Identity $Identity
    $BusinessPage | Export-Excel -Path  $Path -WorksheetName "Business" -StartRow 10 -Title "Page Settings" -TableStyle Medium3 -AutoSize

    Write-Host "Exporting Booking Policy."
    $BookingPolicy = GetGraphBookingBusinessBookingPolicy -Identity $Identity
    $BookingPolicy | Export-Excel -Path  $Path -WorksheetName "Business" -BoldTopRow  -StartRow 10 -StartColumn 10 -Title "Scheduling Policy" -TableStyle Medium3 -AutoSize

    Write-Host "Exporting Working Hours."
    $WorkingHours = GetGraphBookingBusinessWorkingHours -Identity $Identity
    $WorkingHours | Export-Excel -Path  $Path -WorksheetName "Business" -BoldTopRow  -StartRow 25  -Title "Working Hours" -TableStyle Medium24 -AutoSize

    Write-Host "Exporting Staff."
    $Staff = Get-GraphBookingsStaff -Identity $Identity
    $Staff | Export-Excel -Path  $Path -WorksheetName "Staff" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Staff List"

    Write-Host "Exporting Services."
    $Services = Get-GraphBookingsServices -Identity $Identity
    $Services | Export-Excel -Path  $Path -WorksheetName "Services" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Services"

    Write-Host "Exporting Custom Questions."
    $CustomQuestions = Get-GraphBookingsCustomQuestions -Identity $Identity
    $CustomQuestions | Export-Excel -Path  $Path -WorksheetName "Custom Questions" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Custom Questions"

    Write-Host "Exporting MessageTrace for the past $($script:MessageTrackingDays) days."
    $script:MessageTrackingLogs | Export-Excel -Path  $Path -WorksheetName "Message Traces" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3

    Write-Host "Exporting Membership Log data to Excel."
    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog
    $ArrayFromStaffLog | Export-Excel -Path  $Path -WorksheetName "Membership Log" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"

    Write-Host "Exporting Internal data to Excel."
    $script:TenantSettings   | Export-Excel -Path  $Path -WorksheetName "Tenant Settings - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Tenant Settings - Internal"
    $script:BookingMBData  | Export-Excel -Path  $Path -WorksheetName "Mailbox Data - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Mailbox Data - Internal"
    $script:MBPermissions | Export-Excel -Path  $Path -WorksheetName "MB Permissions-Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "MB Permissions - Internal"
    $script:MBRecipientPermissions | Export-Excel -Path  $Path -WorksheetName "Recipient Permissions-Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-tableTitle "Recipient Permissions - Internal"

    Write-Host -ForegroundColor Green "Exporting to Excel Completed. File saved at $Path"
}
