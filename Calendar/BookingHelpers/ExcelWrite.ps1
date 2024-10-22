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

function GetExcelParams($path, $tabName) {

    return @{
        Path                    = $path
        FreezeTopRow            = $true
        Verbose                 = $false
        TableStyle              = "Medium3"
        WorksheetName           = $tabName
        TableName               = $tabName
        FreezeTopRowFirstColumn = $false
        AutoFilter              = $true
        AutoNameRange           = $true
        Append                  = $true
        AutoSize                = $true
        Title                   = "Bookings Support Data Collector"
        ConditionalText         = $ConditionalFormatting
    }
}

function ExcelWrite {
    param($identity)

    Write-Host -ForegroundColor Gray "Checking Excel, Graph and bookings modules"
    CheckExcelModuleInstalled
    CheckGraphAuthModuleInstalled
    CheckGraphBookingsModuleInstalled

    $modulesInstalled = CheckGraphModulesInstalled
    Write-Verbose "Modules installed: $modulesInstalled"
    if ($modulesInstalled -eq $false) {
        Write-Host -ForegroundColor Red "Graph modules are not installed. Exiting..."
        exit
    }

    Connect-MgGraph -Scopes "User.Read.All", "Bookings.Read.All" -NoWelcome

    Write-Host -ForegroundColor Green "Exporting to Excel..."

    #Compose File name formatted as: BookingsSummary_<IdentityName>_<yyyy-MM-dd>_<HHmm>.xlsx
    $IdentityName = SplitIdentityFromEmail -email $identity
    $DateStringToFileName = (Get-Date).ToString("yyyy-MM-dd")
    $HourStringToFileName = Get-Date -Format "HHmm"
    $path = "BookingsSummary_$($IdentityName)_$($DateStringToFileName)_$($HourStringToFileName).xlsx"
    Remove-Item -Path $path -Force -EA Ignore

    $ExcelParamsArray = GetExcelParams -path $path -tabName "Business"

    Write-Host "Exporting Booking Business."
    $BusinessData = GetGraphBookingBusiness -Identity $identity
    $excel = $BusinessData | Export-Excel @ExcelParamsArray -PassThru
    Export-Excel -ExcelPackage $excel -WorksheetName "Business" -MoveToStart

    Write-Host "Exporting Bookings Page Settings."
    $BusinessPage = GetGraphBookingBusinessPage -Identity $identity
    $BusinessPage | Export-Excel -Path  $path -WorksheetName "Business" -StartRow 10 -Title "Page Settings" -TableStyle Medium3 -AutoSize

    Write-Host "Exporting Booking Policy."
    $BookingPolicy = GetGraphBookingBusinessBookingPolicy -Identity $identity
    $BookingPolicy | Export-Excel -Path  $path -WorksheetName "Business" -BoldTopRow  -StartRow 10 -StartColumn 10 -Title "Scheduling Policy" -TableStyle Medium3 -AutoSize

    Write-Host "Exporting Working Hours."
    $WorkingHours = GetGraphBookingBusinessWorkingHours -Identity $identity
    $WorkingHours | Export-Excel -Path  $path -WorksheetName "Business" -BoldTopRow  -StartRow 25  -Title "Working Hours" -TableStyle Medium24 -AutoSize

    Write-Host "Exporting Staff."
    $Staff = Get-GraphBookingsStaff -Identity $identity
    $Staff | Export-Excel -Path  $path -WorksheetName "Staff" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Staff List"

    Write-Host "Exporting Services."
    $Services = Get-GraphBookingsServices -Identity $identity
    $Services | Export-Excel -Path  $path -WorksheetName "Services" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Services"

    Write-Host "Exporting Custom Questions."
    #Get-MgBookingBusinessCustomQuestion -BookingBusinessId $identity | Export-Excel -Path  $path -WorksheetName "Custom Questions" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd
    $CustomQuestions = Get-GraphBookingsCustomQuestions -Identity $identity
    $CustomQuestions | Export-Excel -Path  $path -WorksheetName "Custom Questions" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Custom Questions"

    Write-Host "Exporting MessageTrace for the past $($script:MessageTrackingDays) days."
    $script:MessageTrackingLogs | Export-Excel -Path  $path -WorksheetName "Message Traces" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3

    Write-Host "Exporting Membership Log data to Excel."
    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog
    $ArrayFromStaffLog | Export-Excel -Path  $path -WorksheetName "Membership Log" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"

    Write-Host "Exporting Internal data to Excel."
    $script:TenantSettings   | Export-Excel -Path  $path -WorksheetName "Tenant Settings - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Tenant Settings - Internal"
    $script:bookingMBData  | Export-Excel -Path  $path -WorksheetName "Mailbox Data - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Mailbox Data - Internal"
    $script:MBPermissions | Export-Excel -Path  $path -WorksheetName "MB Permissions-Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "MB Permissions - Internal"
    $script:MBRecipientPermissions | Export-Excel -Path  $path -WorksheetName "Recipient Permissions-Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-tableTitle "Recipient Permissions - Internal"

    # $dateNow = Get-Date
    # $dateStart = $dateNow.AddDays($script:MessageTrackingDays*-5)
    # $params = @{
    #     staffIds      = @(
    #         (Get-MgBookingBusinessStaffMember -BookingBusinessId $identity).Id
    #     )
    #     startDateTime = @{
    #         dateTime = $dateStart.ToString("yyyy-MM-ddT00:00:00")
    #         timeZone = "UTC"
    #     }
    #     endDateTime   = @{
    #         dateTime = $dateNow.ToString("yyyy-MM-ddT00:00:00")
    #         timeZone = "UTC"
    #     }
    # }
    # Get-MgBookingBusinessStaffAvailability -BookingBusinessId $identity -BodyParameter $params | Export-Excel -Path  $path -WorksheetName "Availability 5 days" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd

    Write-Host -ForegroundColor Green "Exporting to Excel Completed. File saved at $path"
}
