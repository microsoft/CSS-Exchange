Function Get-ExchangeBasicServerObject {
    param(
        [Parameter(Mandatory = $true)][string]$ServerName,
        [Parameter(Mandatory = $false)][bool]$AddGetServerProperty = $false
    )
    Write-ScriptDebug("Function Enter: Get-ExchangeBasicServerObject")
    Write-ScriptDebug("Passed: [string]ServerName: {0}" -f $ServerName)
    try {
        $exchServerObject = New-Object PSCustomObject
        $exchServerObject | Add-Member -MemberType NoteProperty -Name ServerName -Value $ServerName
        $getExchangeServer = Get-ExchangeServer $ServerName -Status -ErrorAction Stop
        if ($AddGetServerProperty) {
            $exchServerObject | Add-Member -MemberType NoteProperty -Name ExchangeServer -Value $getExchangeServer
        }
    } catch {
        Write-ScriptHost -WriteString ("Failed to detect server {0} as an Exchange Server" -f $ServerName) -ShowServer $false -ForegroundColor "Red"
        return $null
    }

    $exchAdminDisplayVersion = $getExchangeServer.AdminDisplayVersion
    $exchServerRole = $getExchangeServer.ServerRole
    Write-ScriptDebug("AdminDisplayVersion: {0} | ServerRole: {1}" -f $exchAdminDisplayVersion.ToString(), $exchServerRole.ToString())
    if ($exchAdminDisplayVersion.GetType().Name -eq "string") {
        $start = $exchAdminDisplayVersion.IndexOf(" ")
        $split = $exchAdminDisplayVersion.Substring( $start + 1, 4).split('.')
        [int]$major = $split[0]
        [int]$minor = $split[1]
    }
    if ($exchAdminDisplayVersion.Major -eq 14 -or $major -eq 14) {
        $exchVersion = 14
    } elseif ($exchAdminDisplayVersion.Major -eq 15 -or $major -eq 15) {
        #determine if 2013/2016/2019
        if ($exchAdminDisplayVersion.Minor -eq 0 -or $minor -eq 0) {
            $exchVersion = 15
        } elseif ($exchAdminDisplayVersion.Minor -eq 1 -or $minor -eq 1) {
            $exchVersion = 16
        } else {
            $exchVersion = 19
        }
    } else {
        Write-ScriptHost -WriteString ("Failed to determine what version server {0} is. AdminDisplayVersion: {1}." -f $ServerName, $exchAdminDisplayVersion.ToString()) -ShowServer $false -ForegroundColor "Red"
        return $true
    }

    Function Confirm-MailboxServer {
        param([string]$Value)
        if ($value -like "*Mailbox*" -and (-not(Confirm-EdgeServer -Value $Value))) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-CASServer {
        param([string]$Value, [int]$Version)
        if ((-not(Confirm-EdgeServer -Value $Value)) -and (($Version -ge 16) -or ($Value -like "*ClientAccess*"))) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-CASOnlyServer {
        param([string]$Value)
        if ($Value -eq "ClientAccess") {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-MailboxOnlyServer {
        param([string]$Value)
        if ($Value -eq "Mailbox") {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-HubServer {
        param([string]$Value, [int]$Version)
        if ((($Version -ge 15) -and (-not (Confirm-CASOnlyServer -Value $Value))) -or ($Value -like "*HubTransport*")) {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-EdgeServer {
        param([string]$Value)
        if ($Value -eq "Edge") {
            return $true
        } else {
            return $false
        }
    }

    Function Confirm-DAGMember {
        param([bool]$MailboxServer, [string]$ServerName)
        if ($MailboxServer) {
            if ($null -ne (Get-MailboxServer $ServerName).DatabaseAvailabilityGroup) {
                return $true
            } else {
                return $false
            }
        } else {
            return $false
        }
    }

    $exchServerObject | Add-Member -MemberType NoteProperty -Name Mailbox -Value (Confirm-MailboxServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CAS -Value (Confirm-CASServer -Value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Hub -Value (Confirm-HubServer -Value $exchServerRole -version $exchVersion)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name CASOnly -Value (Confirm-CASOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name MailboxOnly -Value (Confirm-MailboxOnlyServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Edge -Value (Confirm-EdgeServer -Value $exchServerRole)
    $exchServerObject | Add-Member -MemberType NoteProperty -Name Version -Value $exchVersion
    $exchServerObject | Add-Member -MemberType NoteProperty -Name DAGMember -Value (Confirm-DAGMember -MailboxServer $exchServerObject.Mailbox -ServerName $exchServerObject.ServerName)

    Write-ScriptDebug("Confirm-MailboxServer: {0} | Confirm-CASServer: {1} | Confirm-HubServer: {2} | Confirm-CASOnlyServer: {3} | Confirm-MailboxOnlyServer: {4} | Confirm-EdgeServer: {5} | Confirm-DAGMember {6} | Version: {7} | AnyTransportSwitchesEnabled: {8}" -f $exchServerObject.Mailbox,
        $exchServerObject.CAS,
        $exchServerObject.Hub,
        $exchServerObject.CASOnly,
        $exchServerObject.MailboxOnly,
        $exchServerObject.Edge,
        $exchServerObject.DAGMember,
        $exchServerObject.Version,
        $Script:AnyTransportSwitchesEnabled
    )

    return $exchServerObject
}