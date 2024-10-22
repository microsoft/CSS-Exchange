# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function GetBookingMBData {
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

function GetGraphBookingBusiness {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusiness -BookingBusinessId $Identity

    $BookingBusinessArray =$null
    $BookingBusinessArray =@()
    $BookingBusinessArray += [PSCustomObject]@{
        DisplayName         = $GraphBookingBusiness.DisplayName
        OwnerEmail          = $GraphBookingBusiness.Email
        IsPublished         = $GraphBookingBusiness.IsPublished
        DefaultCurrencyIso  = $GraphBookingBusiness.DefaultCurrencyIso
        DefaultTimeZone     = $GraphBookingBusiness.DefaultTimeZone
        LanguageTag         = $GraphBookingBusiness.LanguageTag
        Phone               = $GraphBookingBusiness.Phone
        PublicUrl           = $GraphBookingBusiness.PublicUrl
        WebSiteUrl          = $GraphBookingBusiness.WebSiteUrl
        CreatedDateTime     = $GraphBookingBusiness.AdditionalProperties["createdDateTime"]
        lastUpdatedDateTime = $GraphBookingBusiness.AdditionalProperties["lastUpdatedDateTime"]
        Address             = "City= " + $GraphBookingBusiness.Address.City + ", `r`n" +
        "CountryOrRegion= " + $GraphBookingBusiness.Address.CountryOrRegion + ", `r`n" +
        "PostalCode= " + $GraphBookingBusiness.Address.PostalCode + ", `r`n" +
        "State= " + $GraphBookingBusiness.Address.State + ", `r`n" +
        "Street= " + $GraphBookingBusiness.Address.Street
    }

    return $BookingBusinessArray
}

function GetGraphBookingBusinessPage {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusiness -BookingBusinessId $Identity

    $BookingBusinessArray =$null
    $BookingBusinessArray  = @()
    foreach ( $pageSetting in $GraphBookingBusiness.AdditionalProperties.bookingPageSettings.Keys) {
        $BookingBusinessArray  += [PSCustomObject]@{
            Key   = $pageSetting
            Value = $GraphBookingBusiness.AdditionalProperties.bookingPageSettings[$pageSetting]
        }
    }

    return $BookingBusinessArray
}

function GetGraphBookingBusinessBookingPolicy {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusiness -BookingBusinessId $Identity

    $BookingBusinessArray =$null
    $BookingBusinessArray  = @()

    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "AllowStaffSelection"
        Value = $GraphBookingBusiness.SchedulingPolicy.AllowStaffSelection
    }
    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "MaximumAdvance"
        Value = "$($GraphBookingBusiness.SchedulingPolicy.MaximumAdvance.Days) days, $($GraphBookingBusiness.SchedulingPolicy.MaximumAdvance.Hours) hours and $($GraphBookingBusiness.SchedulingPolicy.MaximumAdvance.Minutes) minutes"
    }
    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "MinimumLeadTime"
        Value = "$($GraphBookingBusiness.SchedulingPolicy.MinimumLeadTime.Days) days, $($GraphBookingBusiness.SchedulingPolicy.MinimumLeadTime.Hours) hours and $($GraphBookingBusiness.SchedulingPolicy.MinimumLeadTime.Minutes) minutes"
    }
    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "SendConfirmationsToOwner"
        Value = $GraphBookingBusiness.SchedulingPolicy.SendConfirmationsToOwner
    }
    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "TimeSlotInterval"
        Value = "$($GraphBookingBusiness.SchedulingPolicy.TimeSlotInterval.Hour) hours and $($GraphBookingBusiness.SchedulingPolicy.TimeSlotInterval.Minute) minutes"
    }
    $BookingBusinessArray  += [PSCustomObject]@{
        Key   = "isMeetingInviteToCustomersEnabled"
        Value = $GraphBookingBusiness.SchedulingPolicy.AdditionalProperties["isMeetingInviteToCustomersEnabled"]
    }

    return $BookingBusinessArray
}

function GetGraphBookingBusinessWorkingHours {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusiness -BookingBusinessId $Identity

    $BookingBusinessArray =$null
    $BookingBusinessArray  = @()
    $BookingBusinessArray  += [PSCustomObject]@{
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
        $max = [System.Math]::Max($max, $GraphBookingBusiness.BusinessHours[0].TimeSlots.Count )
    }

    for ($i = 0; $i -le $max; $i++) {
        $Monday = ""
        $Tuesday = ""
        $Wednesday = ""
        $Thursday = ""
        $Friday = ""
        $Saturday = ""
        $Sunday = ""

        if ($GraphBookingBusiness.BusinessHours[0].TimeSlots) {
            #ternary operator ? : only works on PS 7
            #$Monday = $i -ge $GraphBookingBusiness.BusinessHours[0].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[0].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[0].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[0].TimeSlots.Count) {
                $Monday = ""
            } else {
                $Monday = $GraphBookingBusiness.BusinessHours[0].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[0].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[1].TimeSlots) {
            #$Tuesday = $i -ge $GraphBookingBusiness.BusinessHours[1].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[1].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[1].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[1].TimeSlots.Count) {
                $Tuesday = ""
            } else {
                $Tuesday = $GraphBookingBusiness.BusinessHours[1].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[1].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[2].TimeSlots) {
            #$Wednesday = $i -ge $GraphBookingBusiness.BusinessHours[2].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[2].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[2].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[2].TimeSlots.Count) {
                $Wednesday = ""
            } else {
                $Wednesday = $GraphBookingBusiness.BusinessHours[2].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[2].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[3].TimeSlots) {
            #$Thursday = $i -ge $GraphBookingBusiness.BusinessHours[3].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[3].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[3].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[3].TimeSlots.Count) {
                $Thursday = ""
            } else {
                $Thursday = $GraphBookingBusiness.BusinessHours[3].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[3].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[4].TimeSlots) {
            #$Friday = $i -ge $GraphBookingBusiness.BusinessHours[4].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[4].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[4].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[4].TimeSlots.Count) {
                $Friday = ""
            } else {
                $Friday = $GraphBookingBusiness.BusinessHours[4].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[4].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[5].TimeSlots) {
            #$Saturday = $i -ge $GraphBookingBusiness.BusinessHours[5].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[5].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[5].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[5].TimeSlots.Count) {
                $Saturday = ""
            } else {
                $Saturday = $GraphBookingBusiness.BusinessHours[5].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[5].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[6].TimeSlots) {
            #$Sunday = $i -ge $GraphBookingBusiness.BusinessHours[6].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[6].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[6].TimeSlots[$i].EndTime.Substring(0, 8)
            if ($i -ge $GraphBookingBusiness.BusinessHours[6].TimeSlots.Count) {
                $Sunday = ""
            } else {
                $Sunday = $GraphBookingBusiness.BusinessHours[6].TimeSlots[$i].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[6].TimeSlots[$i].EndTime.Substring(0, 8)
            }
        }

        $BookingBusinessArray  += [PSCustomObject]@{
            Monday    = $Monday
            Tuesday   = $Tuesday
            Wednesday = $Wednesday
            Thursday  = $Thursday
            Friday    = $Friday
            Saturday  = $Saturday
            Sunday    = $Sunday
        }
    }

    return $BookingBusinessArray
}
