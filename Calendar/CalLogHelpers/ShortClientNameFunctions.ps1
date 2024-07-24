# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ===================================================================================================
# Functions to support the script
# ===================================================================================================
function FindMatch {
    param(
        #  [HashTable] $ShortClientNameProcessor,
        [string] $KeyInput
    )
    foreach ($Val in $ShortClientNameProcessor.keys) {
        if ($KeyInput -like "*$Val*") {
            return $ShortClientNameProcessor[$Val]
        }
    }
}

$ShortClientNameProcessor = @{
    'Client=Hub Transport'                       = "Transport"
    'Client=MSExchangeRPC'                       = "Outlook : Desktop : MAPI"
    'OneOutlook'                                 = "OneOutlook"
    'Lync for Mac'                               = "LyncMac"
    'MicrosoftNinja'                             = "Teams"
    'SkypeSpaces'                                = "Teams"
    'Remove-CalendarEvents'                      = "RemoveCalendarEvent"
    'Client=POP3/IMAP4'                          = "PopImap"
    'Client=OWA'                                 = "OWA"
    'PublishedBookingCalendar'                   = "BookingAgent"
    'LocationAssistantProcessor'                 = "LocationProcessor"
    'AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d' = "CalendarReplication"
    'AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0' = "CiscoWebex"
    'AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f' = "Time Service"
    'AppId=48af08dc-f6d2-435f-b2a7-069abd99c086' = "RestConnector"
    'AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419' = "Bookings B2 Service"
    'AppId=82f45fb0-18b4-4d68-8bed-9e44909e3890' = "SkypeMMS"
    'AppId=00000004-0000-0ff1-ce00-000000000000' = "SkypeMMS"
    'GriffinRestClient'                          = "GriffinRestClient"
    'MacOutlook'                                 = "MacOutlookRest"
    'Outlook-iOS-Android'                        = "OutlookMobile"
    'Client=OutlookService;Outlook-Android'      = "OutlookAndroid"
    'Client=OutlookService;Outlook-iOS'          = "OutlookiOS"
}

<#
.SYNOPSIS
Creates friendly / short client names from the LogClientInfoString
#>
function CreateShortClientName {
    param(
        $LogClientInfoString
    )
    $ShortClientName= ""

    # Map LogClientInfoString to ShortClientName
    if ([string]::IsNullOrEmpty($LogClientInfoString)) {
        $ShortClientName = "NotFound"
        return $ShortClientName
    }

    if ($LogClientInfoString -like "*EDiscoverySearch*") {
        $ShortClientName = "EDiscoverySearch"
        return $ShortClientName
    }

    if ($LogClientInfoString -like "Client=EBA*" -or $LogClientInfoString -like "Client=TBA*") {
        if ($LogClientInfoString -like "*ResourceBookingAssistant*") {
            $ShortClientName = "ResourceBookingAssistant"
        } elseif ($LogClientInfoString -like "*CalendarRepairAssistant*") {
            $ShortClientName = "CalendarRepairAssistant"
        } elseif ($LogClientInfoString -like "*SharingSyncAssistant*") {
            $ShortClientName = "CalendarSyncAssistant"
        } else {
            if ($LogClientInfoString -like "*EBA*") {
                $ShortClientName = "Other EBA"
            } else {
                $ShortClientName = "Other TBA"
            }
        }
    } elseif ($LogClientInfoString -like "Client=ActiveSync*") {
        if ($LogClientInfoString -match 'UserAgent=(\w*-\w*)') {
            $ShortClientName = ($LogClientInfoString -split "UserAgent=")[-1].Split("/")[0]
        } elseif ($LogClientInfoString -like "*Outlook-iOS-Android*") {
            $ShortClientName = "OutlookMobile"
        } else {
            $ShortClientName = "ActiveSyncUnknown"
        }
    } elseif ($LogClientInfoString -like "Client=Rest*") {
        if ($LogClientInfoString -like "*LocationAssistantProcessor*") {
            $ShortClientName = "LocationProcessor"
        } elseif ($LogClientInfoString -like "*AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d*") {
            $ShortClientName = "CalendarReplication"
        } elseif ($LogClientInfoString -like "*AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0*") {
            $ShortClientName = "CiscoWebex"
        } elseif ($LogClientInfoString -like "*AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f*") {
            $ShortClientName = "TimeService"
        } elseif ($LogClientInfoString -like "*AppId=48af08dc-f6d2-435f-b2a7-069abd99c086*") {
            $ShortClientName = "RestConnector"
        } elseif ($LogClientInfoString -like "*Client=OutlookService;Outlook-Android*") {
            $ShortClientName = "OutlookAndroid"
        } elseif ($LogClientInfoString -like "*GriffinRestClient*") {
            $ShortClientName = "GriffinRestClient"
        } elseif ($LogClientInfoString -like "*MacOutlook*") {
            $ShortClientName = "MacOutlookRest"
        } elseif ($LogClientInfoString -like "*Microsoft Outlook 16*") {
            $ShortClientName = "Outlook-ModernCalendarSharing"
        } elseif ($LogClientInfoString -like "*SkypeSpaces*") {
            $ShortClientName = "Teams"
        } elseif ($LogClientInfoString -like "*AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419*") {
            $ShortClientName = "Bookings B2 Service"
        } elseif ($LogClientInfoString -like "*bcad1a65-78eb-4725-9bce-ce1a8ed30b95*" -or
            $LogClientInfoString -like "*43375d74-c6a5-4d4e-a0a3-de139860ea75*" -or
            $LogClientInfoString -like "*af9fc99a-5ae5-46e1-bbd7-fa25088e16c9*") {
            $ShortClientName = "ELC-B2"
        } elseif ($LogClientInfoString -like "*Outlook-iOS*") {
            $ShortClientName = "OutlookiOS"
        } elseif ($LogClientInfoString -like "*Outlook-Android*") {
            $ShortClientName = "OutlookAndroid"
        } elseif ($LogClientInfoString -like "*NoUserAgent*") {
            $ShortClientName = "RestUnknown"
        } else {
            $ShortClientName = "[Unknown Rest Client]"
        }
        #    Client=WebServices;Mozilla/5.0 (ZoomPresence.Android 8.1.0 x86);
    } elseif ($ShortClientName -eq "") {
        $ShortClientName = findMatch -KeyInput $LogClientInfoString
    }

    # if ($ShortClientName -eq "" -And $LogClientInfoString -like "Client=WebServices*") {
    if ($LogClientInfoString -like "Client=WebServices*") {
        if ($LogClientInfoString -like "*ZoomPresence*") {
            $ShortClientName = "ZoomPresence"
        } elseif ($LogClientInfoString -like "*MacOutlook*") {
            $ShortClientName = "Outlook : Mac : EWS"
        } elseif ($LogClientInfoString -like "*Outlook*") {
            $ShortClientName = "Outlook : Desktop"
        } elseif ($LogClientInfoString -like "*Ninja*") {
            $ShortClientName = "Teams"
        } else {
            $ShortClientName = "Unknown EWS App"
        }
    }

    if ($LogClientInfoString -like "*InternalCalendarSharing*" ) {
        if ($LogClientInfoString -like "*OWA*" -and
            $LogClientInfoString -notlike "*OneOutlook*") {
            $ShortClientName = "OWA : REST"
        } elseif ($LogClientInfoString -like "*Outlook*" -and
            $LogClientInfoString -notlike "*OneOutlook*" -and
            $LogClientInfoString -notlike "*Outlook-Android*" -and
            $LogClientInfoString -notlike "*Outlook-iOS*") {
            $ShortClientName = "Outlook : Desktop : REST"
        } elseif ($LogClientInfoString -like "*OneOutlook*") {
            $ShortClientName = "OneOutlook"
        }
    }

    if ($LogClientInfoString -like "Client=ActiveSync*" -and $LogClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook : ActiveSync"
    }
    if ($LogClientInfoString -like "*OneOutlook*") {
        $ShortClientName = "OneOutlook"
    }
    if ($ShortClientName -eq "") {
        $ShortClientName = "[NoShortNameFound]"
    }

    return $ShortClientName
}
