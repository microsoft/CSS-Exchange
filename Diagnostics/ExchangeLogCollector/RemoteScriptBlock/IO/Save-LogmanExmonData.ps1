# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Save-LogmanExmonData {
    Get-LogmanData -LogmanName $PassedInfo.ExmonLogmanName -ServerName $env:COMPUTERNAME
}
