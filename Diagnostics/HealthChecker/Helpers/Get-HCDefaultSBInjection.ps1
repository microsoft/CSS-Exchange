# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\ScriptBlockFunctions\Get-DefaultSBInjectionContext.ps1

# Used to get the default SB Injection for Health Checker
function Get-HCDefaultSBInjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$PrimaryScriptBlock,

        [string[]]$IncludeUsingVariableName,

        [ScriptBlock[]]$IncludeScriptBlock
    )
    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $addScriptBlocks = @(${Function:Invoke-CatchActions}, ${Function:Invoke-CatchActionErrorLoop}, ${Function:Write-VerboseErrorInformation},
            ${Function:WriteErrorInformationBase}, ${Function:Invoke-CatchActionError}, ${Function:Invoke-ErrorCatchActionLoopFromIndex})
        $includeScriptBlockList = New-Object System.Collections.Generic.List[ScriptBlock]
        $includeUsingVariableNameList = New-Object System.Collections.Generic.List[string]

        foreach ($sb in $addScriptBlocks) {
            if ($null -eq $sb) {
                throw "Missing default Script Blocks that we should be adding"
            }

            $includeScriptBlockList.Add($sb)
        }

        foreach ($sb in $IncludeScriptBlock) {
            $includeScriptBlockList.Add($sb)
        }

        foreach ($var in $IncludeUsingVariableName) {
            $includeUsingVariableNameList.Add($var)
        }

        $params = @{
            PrimaryScriptBlock       = $PrimaryScriptBlock
            IncludeUsingVariableName = $includeUsingVariableNameList
            IncludeScriptBlock       = $includeScriptBlockList
            CatchActionFunction      = ${Function:Invoke-CatchActions}
        }

        return (Get-DefaultSBInjectionContext @params)
    }
}
