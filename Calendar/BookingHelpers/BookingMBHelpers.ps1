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

    return [PSCustomObject]@{
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
}

function Get-MgBookingBusinessCache {
    param(
        [string]$BookingBusinessId
    )

    if ($null -eq $Script:cachedGetMgBookingBusiness) { $Script:cachedGetMgBookingBusiness = @{} }
    # Keep in mind that key would be case sensitive
    if ($Script:cachedGetMgBookingBusiness.ContainsKey($BookingBusinessId)) {
        return $Script:cachedGetMgBookingBusiness[$BookingBusinessId]
    }

    $GraphBookingBusiness = Get-MgBookingBusiness -BookingBusinessId $BookingBusinessId

    # Determine if/how you want to handle a possible error from the cmdlet or a null value here
    $Script:cachedGetMgBookingBusiness.Add($BookingBusinessId, $GraphBookingBusiness)
    return $GraphBookingBusiness
}

function GetGraphBookingBusiness {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusinessCache -BookingBusinessId $Identity

    return [PSCustomObject]@{
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
}

function GetGraphBookingBusinessPage {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusinessCache -BookingBusinessId $Identity

    $BookingBusinessArray =$null
    $BookingBusinessArray  = @()
    foreach ( $PageSetting in $GraphBookingBusiness.AdditionalProperties.bookingPageSettings.Keys) {
        $BookingBusinessArray  += [PSCustomObject]@{
            Key   = $PageSetting
            Value = $GraphBookingBusiness.AdditionalProperties.bookingPageSettings[$PageSetting]
        }
    }

    return $BookingBusinessArray
}

function GetGraphBookingBusinessBookingPolicy {
    param (
        [string]$Identity
    )

    $GraphBookingBusiness = Get-MgBookingBusinessCache -BookingBusinessId $Identity

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

    $GraphBookingBusiness = Get-MgBookingBusinessCache -BookingBusinessId $Identity

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
    # need to run loop so that I get a 2Dimensional data array at the end with the string values usable by Excel Export Module
    $Max = 0
    for ($I = 0; $I -le 7; $I++) {
        $Max = [System.Math]::Max($Max, $GraphBookingBusiness.BusinessHours[0].TimeSlots.Count )
    }

    for ($I = 0; $I -le $Max; $I++) {
        $Monday = ""
        $Tuesday = ""
        $Wednesday = ""
        $Thursday = ""
        $Friday = ""
        $Saturday = ""
        $Sunday = ""

        if ($GraphBookingBusiness.BusinessHours[0].TimeSlots) {
            if ($I -ge $GraphBookingBusiness.BusinessHours[0].TimeSlots.Count) {
                $Monday = ""
            } else {
                $Monday = $GraphBookingBusiness.BusinessHours[0].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[0].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[1].TimeSlots) {
            # $Tuesday = $I -ge $GraphBookingBusiness.BusinessHours[1].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[1].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[1].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[1].TimeSlots.Count) {
                $Tuesday = ""
            } else {
                $Tuesday = $GraphBookingBusiness.BusinessHours[1].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[1].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[2].TimeSlots) {
            # $Wednesday = $I -ge $GraphBookingBusiness.BusinessHours[2].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[2].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[2].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[2].TimeSlots.Count) {
                $Wednesday = ""
            } else {
                $Wednesday = $GraphBookingBusiness.BusinessHours[2].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[2].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[3].TimeSlots) {
            # $Thursday = $I -ge $GraphBookingBusiness.BusinessHours[3].TimeSlots.Count  ? "": $GraphBookingBusiness.BusinessHours[3].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[3].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[3].TimeSlots.Count) {
                $Thursday = ""
            } else {
                $Thursday = $GraphBookingBusiness.BusinessHours[3].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[3].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[4].TimeSlots) {
            # $Friday = $I -ge $GraphBookingBusiness.BusinessHours[4].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[4].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[4].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[4].TimeSlots.Count) {
                $Friday = ""
            } else {
                $Friday = $GraphBookingBusiness.BusinessHours[4].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[4].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[5].TimeSlots) {
            # $Saturday = $I -ge $GraphBookingBusiness.BusinessHours[5].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[5].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[5].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[5].TimeSlots.Count) {
                $Saturday = ""
            } else {
                $Saturday = $GraphBookingBusiness.BusinessHours[5].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[5].TimeSlots[$I].EndTime.Substring(0, 8)
            }
        }
        if ($GraphBookingBusiness.BusinessHours[6].TimeSlots) {
            # $Sunday = $I -ge $GraphBookingBusiness.BusinessHours[6].TimeSlots.Count ? "": $GraphBookingBusiness.BusinessHours[6].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[6].TimeSlots[$I].EndTime.Substring(0, 8)
            if ($I -ge $GraphBookingBusiness.BusinessHours[6].TimeSlots.Count) {
                $Sunday = ""
            } else {
                $Sunday = $GraphBookingBusiness.BusinessHours[6].TimeSlots[$I].StartTime.Substring(0, 8) + " to " + $GraphBookingBusiness.BusinessHours[6].TimeSlots[$I].EndTime.Substring(0, 8)
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
