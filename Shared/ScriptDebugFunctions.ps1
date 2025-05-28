# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-DebugObject {
    [CmdletBinding()]
    param()
    process {
        if ($null -eq $Script:savedDebugObject) {
            Write-Verbose "Creating Get-DebugObject Hashtable"
            $Script:savedDebugObject = @{}
        }
        $Script:savedDebugObject
    }
}

function Add-DebugObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectKeyName,

        [Parameter(Mandatory = $false)]
        [object]$ObjectValueEntry
    )
    begin {
        $getDebugObject = Get-DebugObject
    }
    process {
        if (-not ($getDebugObject.ContainsKey($ObjectKeyName))) {
            $getDebugObject.Add($ObjectKeyName, (New-Object System.Collections.Generic.List[object]))
        }
        $getDebugObject[$ObjectKeyName].Add($ObjectValueEntry)
    }
}

<#
    $MyInvocation.ScriptLineNumber provides the caller's line. Not where it is at being used in the script.
    That is why this needs to be it's own function.
#>
function Get-ScriptDebugLine {
    $MyInvocation.ScriptLineNumber
}
