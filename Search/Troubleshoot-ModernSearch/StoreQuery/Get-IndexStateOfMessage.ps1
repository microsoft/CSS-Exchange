# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-IndexStateOfMessage {
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

        if ($Message.p365A0003 -gt 0) {
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

