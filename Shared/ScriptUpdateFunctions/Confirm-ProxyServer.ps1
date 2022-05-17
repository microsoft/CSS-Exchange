# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Confirm-ProxyServer {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TargetUri
    )

    try {
        $proxyObject = ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($TargetUri)
        if ($TargetUri -ne $proxyObject.OriginalString) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}
