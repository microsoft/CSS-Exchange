# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\Shared\Out-Columns.ps1

function Write-DebugLog($Message) {
    $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $Message
}

function Write-HostLog($Message) {
    $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $Message
    Write-DebugLog $Message
}

function Write-OutColumns {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object[]]
        $InputObject,

        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]
        $Properties,

        [Parameter(Mandatory = $false, Position = 1)]
        [ScriptBlock[]]
        $ColorizerFunctions = @(),

        [Parameter(Mandatory = $false)]
        [int]
        $IndentSpaces = 0,

        [Parameter(Mandatory = $false)]
        [int]
        $LinesBetweenObjects = 0
    )
    begin {
        $objects = New-Object System.Collections.ArrayList
    }
    process {
        foreach ($thing in $InputObject) {
            [void]$objects.Add($thing)
        }
    }
    end {
        $stringOutput = [string]::Empty
        SetWriteHostAction $null
        $objects | Out-Columns -Properties $Properties `
            -ColorizerFunctions $ColorizerFunctions `
            -IndentSpaces $IndentSpaces `
            -LinesBetweenObjects $LinesBetweenObjects `
            -StringOutput ([ref]$stringOutput)
        Write-HostLog $stringOutput
        SetWriteHostAction ${Function:Write-HostLog}
    }
}
