# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# CreateShortClientName.ps1
# This script is used to support the Get-CalendarDiagnosticObjectsSummary.ps1 script.
<#
.SYNOPSIS
Creates friendly / short client names from the ClientInfoString
#>
function CreateShortClientName {
    param(
        $ClientInfoString
    )
    $ShortClientName= @()

    # Map ClientInfoString to ShortClientName
    if (!$ClientInfoString) {
        $ShortClientName = "NotFound"
    }

    if ($ClientInfoString -like "Client=EBA*" -or $ClientInfoString -like "Client=TBA*") {
        if ($ClientInfoString -like "*ResourceBookingAssistant*") {
            $ShortClientName = "ResourceBookingAssistant"
        } elseif ($ClientInfoString -like "*CalendarRepairAssistant*") {
            $ShortClientName = "CalendarRepairAssistant"
        } else {
            $client = $ClientInfoString.Split(';')[0].Split('=')[-1]
            $Action = $ClientInfoString.Split(';')[1].Split('=')[-1]
            $Data = $ClientInfoString.Split(';')[-1]
            $ShortClientName = $client+":"+$Action+";"+$Data
        }
    } elseif ($ClientInfoString -like "Client=ActiveSync*") {
        if ($ClientInfoString -match 'UserAgent=(\w*-\w*)') {
            $ShortClientName = ($ClientInfoString -split "UserAgent=")[-1].Split("/")[0]
        } elseif ($ClientInfoString -like "*Outlook-iOS-Android*") {
            $ShortClientName = "OutlookMobile"
        } else {
            $ShortClientName = "ActiveSyncUnknown"
        }
    } elseif ($ClientInfoString -like "Client=Rest*") {
        if ($ClientInfoString -like "*LocationAssistantProcessor*") {
            $ShortClientName = "LocationProcessor"
        } elseif ($ClientInfoString -like "*AppId=6326e366-9d6d-4c70-b22a-34c7ea72d73d*") {
            $ShortClientName = "CalendarReplication"
        } elseif ($ClientInfoString -like "*AppId=1e3faf23-d2d2-456a-9e3e-55db63b869b0*") {
            $ShortClientName = "CiscoWebex"
        } elseif ($ClientInfoString -like "*AppId=1c3a76cc-470a-46d7-8ba9-713cfbb2c01f*") {
            $ShortClientName = "TimeService"
        } elseif ($ClientInfoString -like "*AppId=48af08dc-f6d2-435f-b2a7-069abd99c086*") {
            $ShortClientName = "RestConnector"
        } elseif ($ClientInfoString -like "*Client=OutlookService;Outlook-Android*") {
            $ShortClientName = "OutlookAndroid"
        } elseif ($ClientInfoString -like "*GriffinRestClient*") {
            $ShortClientName = "GriffinRestClient"
        } elseif ($ClientInfoString -like "*MacOutlook*") {
            $ShortClientName = "MacOutlookRest"
        } elseif ($ClientInfoString -like "*Microsoft Outlook 16*") {
            $ShortClientName = "Outlook-ModernCalendarSharing"
        } elseif ($ClientInfoString -like "*SkypeSpaces*") {
            $ShortClientName = "Teams"
        } elseif ($ClientInfoString -like "*AppId=7b7fdad6-df9d-4cd5-a4f2-b5f749350419*") {
            $ShortClientName = "Bookings B2 Service"
        } elseif ($ClientInfoString -like "*bcad1a65-78eb-4725-9bce-ce1a8ed30b95*" -or
            $ClientInfoString -like "*43375d74-c6a5-4d4e-a0a3-de139860ea75*" -or
            $ClientInfoString -like "*af9fc99a-5ae5-46e1-bbd7-fa25088e16c9*") {
            $ShortClientName = "ELC-B2"
        } elseif ($ClientInfoString -like "*NoUserAgent*") {
            $ShortClientName = "RestUnknown"
        } else {
            $ShortClientName = "[Unknown Rest Client]"
        }
        #    Client=WebServices;Mozilla/5.0 (ZoomPresence.Android 8.1.0 x86);
    } else {
        $ShortClientName = findMatch -PassedHash $ShortClientNameProcessor
    }

    if ($ShortClientName -eq "" -And $ClientInfoString -like "Client=WebServices*") {
        if ($ClientInfoString -like "*ZoomPresence*") {
            $ShortClientName = "ZoomPresence"
        } else {
            $ShortClientName = "Unknown EWS App"
        }
    }

    if ($ClientInfoString -like "*InternalCalendarSharing*" -and
        $ClientInfoString -like "*OWA*" -and
        $ClientInfoString -notlike "*OneOutlook*") {
        $ShortClientName = "Owa-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*MacOutlook*") {
        $ShortClientName = "MacOutlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*InternalCalendarSharing*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "Client=ActiveSync*" -and $ClientInfoString -like "*Outlook*") {
        $ShortClientName = "Outlook-ModernCalendarSharing"
    }
    if ($ClientInfoString -like "*OneOutlook*") {
        $ShortClientName = "OneOutlook"
    }
    if ($ShortClientName -eq "") {
        $ShortClientName = "[NoShortNameFound]"
    }

    return $ShortClientName
}


$ShortClientNameProcessor = @{
    'Client=Hub Transport'                       = "Transport"
    'Client=MSExchangeRPC'                       = "Outlook-MAPI"
    'OneOutlook'                                 = "OneOutlook"
    'Lync for Mac'                               = "LyncMac"
    'AppId=00000004-0000-0ff1-ce00-000000000000' = "SkypeMMS"
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
    'GriffinRestClient'                          = "GriffinRestClient"
    'MacOutlook'                                 = "MacOutlookRest"
    'Outlook-iOS-Android'                        = "OutlookMobile"
    'Client=OutlookService;Outlook-Android'      = "OutlookAndroid"
    'Client=OutlookService;Outlook-iOS'          = "OutlookiOS"
}
