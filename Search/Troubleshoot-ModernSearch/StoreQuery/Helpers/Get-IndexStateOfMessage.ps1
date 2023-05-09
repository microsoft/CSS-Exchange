# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Takes the message to get the current determined index state.
        ShouldNotBeIndexed - If BigFunnelPoiNotNeededReason (p365A0003) has any value besides 0 besides NULL
        Indexed - If BigFunnelPOISize has value and BigFunnelPOIIsUpToDate (p3655000B) is set to true
                    while IsPartiallyIndexed property is not set to NULL or False
        PartiallyIndexed -  If BigFunnelPOISize has value and BigFunnelPOIIsUpToDate (p3655000B) is set to true
                    while IsPartiallyIndexed property is set to True
        NotIndexed - If BigFunnelPOISize is NULL or a value of 0 and BigFunnelPOIIsUpToDate (p3655000B) is set to NULL or False
        Corrupted - If BigFunnelPOISize is NULL or a value of 0 and BigFunnelPOIIsUpToDate (p3655000B) is set to True
        Stale - If BigFunnelPOISize has a value and BigFunnelPOIIsUpToDate (p3655000B) is set to NULL or False
#>
function Get-IndexStateOfMessage {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Message,

        [Parameter(Mandatory = $true)]
        [object]$BigFunnelPropNameMapping
    )
    begin {
        $status = "Unknown"
    }
    process {

        if ($Message.p365A0003 -gt 0 -and
            $Message.p365A0003.ToString() -ne "NULL") {
            $status = "ShouldNotBeIndexed"
        } elseif ($Message.BigFunnelPOISize -gt 0 -and
            $Message.BigFunnelPOISize -ne "NULL" -and
            $Message.p3655000B -eq $true -and
            ($Message.($BigFunnelPropNameMapping.IsPartiallyIndexed).ToString() -eq "NULL" -or
            $Message.($BigFunnelPropNameMapping.IsPartiallyIndexed) -eq $false)) {
            $status = "Indexed"
        } elseif ($Message.BigFunnelPOISize -gt 0 -and
            $Message.BigFunnelPOISize -ne "NULL" -and
            $Message.p3655000B -eq $true -and
            $Message.($BigFunnelPropNameMapping.IsPartiallyIndexed) -eq $true) {
            $status = "PartiallyIndexed"
        } elseif (($Message.BigFunnelPOISize -eq "NULL" -or
                $Message.BigFunnelPOISize -le 0) -and
            ($Message.p3655000B.ToString() -eq "NULL" -or
            $Message.p3655000B -eq $false)) {
            $status = "NotIndexed"
        } elseif (($Message.BigFunnelPOISize -eq "NULL" -or
                $Message.BigFunnelPOISize -le 0) -and
            $Message.p3655000B -eq $true) {
            $status = "Corrupted"
        } elseif ($Message.BigFunnelPOISize -gt 0 -and
            ($Message.p3655000B.ToString() -eq "NULL" -or
            $Message.p3655000B -eq $false)) {
            $status = "Stale"
        }
    }
    end {
        return $status
    }
}
