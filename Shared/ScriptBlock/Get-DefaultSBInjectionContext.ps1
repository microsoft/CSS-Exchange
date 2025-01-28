# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\OutputOverrides\Write-Progress.ps1
. $PSScriptRoot\Add-ScriptBlockInjection.ps1
. $PSScriptRoot\RemoteSBLoggingFunctions.ps1

<#
.SYNOPSIS
    This function utilized Add-ScriptBlockInjection and will automatically include the required variables
    and script blocks needed within the project to handle logging in a remote script block.
.DESCRIPTION
    By default this will include, if they are overridden, the script blocks for the functions:
        Write-Verbose
        Write-Progress
        Write-Host
    The reason why these are overridden is to allow the code to be execute by itself and still work correctly.
    So instead of creating a function called Write-VerboseAndLog to Write-Verbose to the screen and log out the information, you can just override Write-Verbose to do this for you.
    The problem comes in when you would like to debug a remote execution in a log to determine a problem. In your overridden functions, you can account for this and have the caller handle this.
.PARAMETER PrimaryScriptBlock
    This is the main script block that we will be injecting everything inside of.
    This is the one that you will be passing your arguments to if there are any and will be executing.
.PARAMETER IncludeUsingVariableName
    Add any additional variables that we wish to provide to the script block with the "$using:" status.
    These are for things that are not included in the passed arguments and are likely script scoped variables in functions that are being injected.
.PARAMETER IncludeScriptBlock
    Additional script blocks that need to be included. The most common ones are going to be like Write-Verbose and Write-Host.
    This then allows the remote script block to manipulate the data that is in Write-Verbose and be returned to the pipeline so it can be logged to the main caller.
.PARAMETER CatchActionFunction
    The script block to be executed if we have an exception while trying to create the injected script block.
#>
function Get-DefaultSBInjectionContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$PrimaryScriptBlock,

        [string[]]$IncludeUsingVariableName,

        [ScriptBlock[]]$IncludeScriptBlock,

        [ScriptBlock]$CatchActionFunction
    )
    process {

        function Get-DefaultManipulatorVerboseMessage {
            [CmdletBinding()]
            [OutputType([string])]
            param(
                [Parameter(Position = 1, ValueFromPipeline)]
                [string]$Message
            )
            process {
                return "[[$([System.DateTime]::Now)] $env:COMPUTERNAME - Remote Logging] : $Message"
            }
        }

        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $defaultScriptBlocks = @(${Function:Write-Verbose}, ${Function:Write-Host}, ${Function:Write-Progress},
            ${Function:New-RemoteLoggingPipelineObject}, ${Function:New-RemoteVerbosePipelineObject}, ${Function:Invoke-RemotePipelineHandler},
            ${Function:New-RemoteHostPipelineObject}, ${Function:New-RemoteProgressPipelineObject})
        $includeScriptBlockList = New-Object System.Collections.Generic.List[ScriptBlock]
        $includeUsingVariableNameList = New-Object System.Collections.Generic.List[string]

        foreach ($sb in $defaultScriptBlocks) {
            if ($null -eq $sb) {
                continue
            }

            # Functions should be here as we are loading them as a dependency.
            if ($sb.Ast.Name -eq "Write-Verbose") {
                Write-Verbose "Set and Add WriteRemoteVerboseDebugAction/WriteVerboseRemoteManipulateMessageAction to using list"
                SetWriteRemoteVerboseAction "New-RemoteVerbosePipelineObject"
                SetWriteVerboseRemoteManipulateMessageAction "Get-DefaultManipulatorVerboseMessage"
                $includeUsingVariableNameList.Add("WriteVerboseRemoteManipulateMessageAction")
                $includeUsingVariableNameList.Add("WriteRemoteVerboseDebugAction")
                $includeScriptBlockList.Add(${Function:Get-DefaultManipulatorVerboseMessage})
            }

            if ($sb.Ast.Name -eq "Write-Progress") {
                Write-Verbose "Set and Add SetWriteRemoteProgressAction to using list"
                SetWriteRemoteProgressAction "New-RemoteProgressPipelineObject"
                $includeUsingVariableNameList.Add("WriteRemoteProgressDebugAction")
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
            CatchActionFunction      = $CatchActionFunction
        }
        return (Add-ScriptBlockInjection @params)
    }
}
