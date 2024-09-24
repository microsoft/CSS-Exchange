. $PSScriptRoot\GraphInstaller.ps1
. $PSScriptRoot\BookingMBHelpers.ps1
. $PSScriptRoot\BookingStaffHelpers.ps1
. $PSScriptRoot\BookingServiceHelpers.ps1
. $PSScriptRoot\BookingCustomQuestionHelpers.ps1
. $PSScriptRoot\BookingStaffLogHelper.ps1

function GetExcelParams($path, $tabName) {

    return @{
        Path                    = $path
        FreezeTopRow            = $true
        #  BoldTopRow              = $true
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

    CheckExcelModuleInstalled
    CheckGraphAuthModuleInstalled
    CheckGraphBookingsModuleInstalled

    Connect-MgGraph -Scopes "User.Read.All", "Bookings.Read.All" -NoWelcome

    $path = 'C:\Temp\BookingsPOC.xlsx'
    Remove-Item -Path $path -Force -EA Ignore

    $ExcelParamsArray = GetExcelParams -path $path -tabName "Business"

    Write-Host "Exporting Booking Business"
    $a = Get-GraphBusiness -Identity $identity
    $excel = $a | Export-Excel @ExcelParamsArray -PassThru
    Export-Excel -ExcelPackage $excel -WorksheetName "Business" -MoveToStart

    Write-Host "Exporting Bookings Page Settings"
    $a = Get-GraphBusinessPage -Identity $identity
    $a | Export-Excel -Path  $path -WorksheetName "Business" -StartRow 10 -Title "Page Settings" -TableStyle Medium3 -AutoSize


    Write-Host "Exporting Booking Policy"
    $a = Get-GraphBusinessBookingPolicy -Identity $identity
    $a | Export-Excel -Path  $path -WorksheetName "Business" -BoldTopRow  -StartRow 10 -StartColumn 10 -Title "Scheduling Policy" -TableStyle Medium3 -AutoSize

    Write-Host "Exporting Working Hours"
    $a = Get-GraphBusinessWorkingHours -Identity $identity
    $a | Export-Excel -Path  $path -WorksheetName "Business" -BoldTopRow  -StartRow 25  -Title "Working Hours" -TableStyle Medium24 -AutoSize


    Write-Host "Exporting Staff"
    $staff = Get-GraphBookingsStaff -Identity $identity
    $staff | Export-Excel -Path  $path -WorksheetName "Staff" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Staff List"

    Write-Host "Exporting Services"
    $services = Get-GraphBookingsServices -Identity $identity
    $services | Export-Excel -Path  $path -WorksheetName "Services" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Services"


    Write-Host "Exporting Custom Questions"
    #Get-MgBookingBusinessCustomQuestion -BookingBusinessId $identity | Export-Excel -Path  $path -WorksheetName "Custom Questions" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd
    $customQuestions = Get-GraphBookingsCustomQuestions -Identity $identity
    $customQuestions | Export-Excel -Path  $path -WorksheetName "Custom Questions" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -Title "Custom Questions"


    Write-Host "Exporting MessageTrace for the past 5 days"
    $script:MessageTrackingLogs | Export-Excel -Path  $path -WorksheetName "Message Traces" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3

    Write-Host "ExportingInternal data to Excel"
    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog
    $ArrayFromStaffLog | Export-Excel -Path  $path -WorksheetName "Membership Log" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"

    Write-Host "ExportingInternal data to Excel"
    $script:TenantSettings   | Export-Excel -Path  $path -WorksheetName "Tenant Settings - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Tenant Settings - Internal"
    $script:bookingMBData  | Export-Excel -Path  $path -WorksheetName "Mailbox Data - Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Mailbox Data - Internal"
    #$script:StaffData  | Export-Excel -Path  $path -WorksheetName "Staff Data-Internal" -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize -TableStyle Medium3 #-Title "Staff Data - Internal"
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



    Write-Host "Exporting to Excel Completed"
}


function export-BookingStaffMembershipLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$identity
    )

    $ArrayFromStaffLog = createArrayFromStaffLog -log $script:BookingStaffMembershipLog.MailboxLog

    $MBStaffMembershipLogArray = @()
    foreach ($log in $script:BookingStaffMembershipLog.MailboxLog.Split("`r`n")) {
        $MBStaffMembershipLogArray += [PSCustomObject]@{
            log = $log
        }
    }
    $MBStaffMembershipLogArray | Export-Excel -Path  $path -WorksheetName "Membership Log Array" -TableStyle Medium3 -AutoFilter -FreezeTopRow -BoldTopRow -MoveToEnd -AutoSize  -Title "Staff Membership Log"
}