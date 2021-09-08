# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function WriteLog {
    process {
        $_ | Out-File -FilePath ".\InstallerCacheLogger.log" -Append
    }
}

Function Write-Host {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Host')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$Object,

        [string]$ForegroundColor = "Gray"
    )

    process {
        $Object | WriteLog
        Microsoft.PowerShell.Utility\Write-Host $Object -ForegroundColor $ForegroundColor
    }
}

Function Write-Output {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Output')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [object]$InputObject
    )
    process {
        $InputObject | WriteLog
        Microsoft.PowerShell.Utility\Write-Output $InputObject
    }
}
