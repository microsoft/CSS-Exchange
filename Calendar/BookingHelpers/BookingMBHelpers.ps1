function Get-BookingMBData {
    param (
        [string]$Identity
    )

    $script:BMB = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
    if ($null -eq $script:BMB) {
        Write-DashLineBoxColor -Line "Booking Mailbox not found" -Color "Red"
        return $null
    }

    $bookingMBData = [PSCustomObject]@{
        DisplayName                   = $script:BMB.DisplayName
        Identity                      = $script:BMB.Identity
        RecipientType                 = $script:BMB.RecipientType  #: UserMailbox
        RecipientTypeDetails          = $script:BMB.RecipientTypeDetails  # SchedulingMailbox
        EmailAddresses                = $script:BMB.EmailAddresses
        IsMailboxEnabled              = $script:BMB.IsMailboxEnabled
        HiddenFromAddressListsEnabled = $script:BMB.HiddenFromAddressListsEnabled
        IsSoftDeletedByRemove         = $script:BMB.IsSoftDeletedByRemove
        IsSoftDeletedByDisable        = $script:BMB.IsSoftDeletedByDisable
        IsInactiveMailbox             = $script:BMB.IsInactiveMailbox
        WhenSoftDeleted               = $script:BMB.WhenSoftDeleted
        WindowsEmailAddress           = $script:BMB.WindowsEmailAddress
        WhenCreated                   = $script:BMB.WhenCreated
        Guid                          = $script:BMB.Guid
        OriginatingServer             = $script:BMB.OriginatingServer
    }
    return $bookingMBData
}




function Get-GraphBusiness {
    param (
        [string]$Identity
    )

    $MB = Get-MgBookingBusiness -BookingBusinessId $Identity

    Write-Host "Exporting Working Hours"

    $a=$null
    $a=@()
    $a+= [PSCustomObject]@{
        DisplayName         = $MB.DisplayName
        OwnerEmail          = $MB.Email
        IsPublished         = $MB.IsPublished
        DefaultCurrencyIso  = $MB.DefaultCurrencyIso
        DefaultTimeZone     = $MB.DefaultTimeZone
        LanguageTag         = $MB.LanguageTag
        Phone               = $MB.Phone
        PublicUrl           = $MB.PublicUrl
        WebSiteUrl          = $MB.WebSiteUrl
        CreatedDateTime     = $MB.AdditionalProperties["createdDateTime"]
        lastUpdatedDateTime = $MB.AdditionalProperties["lastUpdatedDateTime"]
        Address             = "City= " + $MB.Address.City + ", `r`n" +
        "CountryOrRegion= " + $MB.Address.CountryOrRegion + ", `r`n" +
        "PostalCode= " + $MB.Address.PostalCode + ", `r`n" +
        "State= " + $MB.Address.State + ", `r`n" +
        "Street= " + $MB.Address.Street
    }

    return $a
}


function Get-GraphBusinessPage {
    param (
        [string]$Identity
    )

    $MB = Get-MgBookingBusiness -BookingBusinessId $Identity

    Write-Host "Exporting Page Settings"

    $a=$null
    $a = @()
    foreach ( $pageSetting in $MB.AdditionalProperties.bookingPageSettings.Keys) {
        $a += [PSCustomObject]@{
            Key   = $pageSetting
            Value = $MB.AdditionalProperties.bookingPageSettings[$pageSetting]
        }
    }

    return $a
}


function Get-GraphBusinessBookingPolicy {
    param (
        [string]$Identity
    )

    $MB = Get-MgBookingBusiness -BookingBusinessId $Identity

    Write-Host "Exporting Booking Policy"

    $a=$null
    $a = @()

    $a += [PSCustomObject]@{
        Key   = "AllowStaffSelection"
        Value = $MB.SchedulingPolicy.AllowStaffSelection
    }
    $a += [PSCustomObject]@{
        Key   = "MaximumAdvance"
        Value = "$($MB.SchedulingPolicy.MaximumAdvance.Days) days, $($MB.SchedulingPolicy.MaximumAdvance.Hours) hours and $($MB.SchedulingPolicy.MaximumAdvance.Minutes) minutes"
    }
    $a += [PSCustomObject]@{
        Key   = "MinimumLeadTime"
        Value = "$($MB.SchedulingPolicy.MinimumLeadTime.Days) days, $($MB.SchedulingPolicy.MinimumLeadTime.Hours) hours and $($MB.SchedulingPolicy.MinimumLeadTime.Minutes) minutes"
    }
    $a += [PSCustomObject]@{
        Key   = "SendConfirmationsToOwner"
        Value = $MB.SchedulingPolicy.SendConfirmationsToOwner
    }
    $a += [PSCustomObject]@{
        Key   = "TimeSlotInterval"
        Value = "$($MB.SchedulingPolicy.TimeSlotInterval.Hour) hours and $($MB.SchedulingPolicy.TimeSlotInterval.Minute) minutes"
    }
    $a += [PSCustomObject]@{
        Key   = "isMeetingInviteToCustomersEnabled"
        Value = $MB.SchedulingPolicy.AdditionalProperties["isMeetingInviteToCustomersEnabled"]
    }

    return $a
}


function Get-GraphBusinessWorkingHours {
    param (
        [string]$Identity
    )

    $MB = Get-MgBookingBusiness -BookingBusinessId $Identity

    Write-Host "Exporting Working Hours"

    $a=$null
    $a = @()
    $a += [PSCustomObject]@{
        Monday    = ""
        Tuesday   = ""
        Wednesday = ""
        Thursday  = ""
        Friday    = ""
        Saturday  = ""
        Sunday    = ""
    }
    #need to run iteractive loop so that I get a 2Dimensional data array at the end with the string values usable by Excel Export Module
    $max = 0
    for ($i = 0; $i -le 7; $i++) {
        $max = [System.Math]::Max($max, $MB.BusinessHours[0].TimeSlots.Count )
    }

    for ($i = 0; $i -le $max; $i++) {
        $monday = ""
        $tuesday = ""
        $wednesday = ""
        $thursday = ""
        $friday = ""
        $saturday = ""
        $sunday = ""

        if ($MB.BusinessHours[0].TimeSlots) {
            #ternary operator ? : only works on PS 7
            #$monday = $i -ge $MB.BusinessHours[0].TimeSlots.Count ? "": $MB.BusinessHours[0].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[0].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[0].TimeSlots.Count) {
                $monday = ""
            } else {
                $monday = $MB.BusinessHours[0].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[0].TimeSlots[$i].EndTime.Substring(0, 8)
            }

        }
        if ($MB.BusinessHours[1].TimeSlots) {
            #$tuesday = $i -ge $MB.BusinessHours[1].TimeSlots.Count  ? "": $MB.BusinessHours[1].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[1].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[1].TimeSlots.Count) {
                $tuesday = ""
            } else {
                $tuesday = $MB.BusinessHours[1].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[1].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($MB.BusinessHours[2].TimeSlots) {
            #$wednesday = $i -ge $MB.BusinessHours[2].TimeSlots.Count  ? "": $MB.BusinessHours[2].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[2].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[2].TimeSlots.Count) {
                $wednesday = ""
            } else {
                $wednesday = $MB.BusinessHours[2].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[2].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($MB.BusinessHours[3].TimeSlots) {
            #$thursday = $i -ge $MB.BusinessHours[3].TimeSlots.Count  ? "": $MB.BusinessHours[3].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[3].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[3].TimeSlots.Count) {
                $thursday = ""
            } else {
                $thursday = $MB.BusinessHours[3].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[3].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($MB.BusinessHours[4].TimeSlots) {
            #$friday = $i -ge $MB.BusinessHours[4].TimeSlots.Count ? "": $MB.BusinessHours[4].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[4].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[4].TimeSlots.Count) {
                $friday = ""
            } else {
                $friday = $MB.BusinessHours[4].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[4].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($MB.BusinessHours[5].TimeSlots) {
            #$saturday = $i -ge $MB.BusinessHours[5].TimeSlots.Count ? "": $MB.BusinessHours[5].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[5].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[5].TimeSlots.Count) {
                $saturday = ""
            } else {
                $saturday = $MB.BusinessHours[5].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[5].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($MB.BusinessHours[6].TimeSlots) {
            #$sunday = $i -ge $MB.BusinessHours[6].TimeSlots.Count ? "": $MB.BusinessHours[6].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[6].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $MB.BusinessHours[6].TimeSlots.Count) {
                $sunday = ""
            } else {
                $sunday = $MB.BusinessHours[6].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $MB.BusinessHours[6].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }

        $a += [PSCustomObject]@{
            Monday    = $monday
            Tuesday   = $tuesday
            Wednesday = $wednesday
            Thursday  = $thursday
            Friday    = $friday
            Saturday  = $saturday
            Sunday    = $sunday
        }
    }

    return $a
}