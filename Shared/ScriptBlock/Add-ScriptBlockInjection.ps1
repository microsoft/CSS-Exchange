# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

<#
.SYNOPSIS
    Takes a script block and injects additional functions that you might want to have included in remote or job script block.
    This prevents duplicate code from being written to bloat the script size.
.DESCRIPTION
    By default, it will inject the Verbose and Debug Preferences and other passed variables into the script block with "using" in the correct usage.
    Within this project, we accounted for Invoke-Command to fail due to WMI issues, therefore we would fallback and execute the script block locally,
    if that the server we wanted to run against. Therefore, if you are use '$Using:VerbosePreference' it would cause a failure.
    So we account for that here as well.
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
.NOTES
    Supported Script Block Creations are:
        [ScriptBlock]::Create(string) and ${Function:Write-Verbose}
    Supported ways to write the function of the script block are defined in the Pester testing file.
    Supported ways of using the return script block:
        Invoke-Command
        Invoke-Command -AsJob
        Start-Job
        & $scriptBlock @params
#>
function Add-ScriptBlockInjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$PrimaryScriptBlock,

        [string[]]$IncludeUsingVariableName,

        [ScriptBlock[]]$IncludeScriptBlock,

        [ScriptBlock]$CatchActionFunction
    )
    process {
        try {
            # In Remote Execution if you want Write-Verbose to work or add in additional
            # Script Blocks to your code to be executed, like a custom Write-Verbose, you need to inject it into the script block
            # that is passed to Invoke-Command.
            Write-Verbose "Calling: $($MyInvocation.MyCommand)"
            $scriptBlockInjectLines = @()
            $scriptBlockFinalized = [string]::Empty
            $adjustedScriptBlock = $PrimaryScriptBlock
            $injectedLinesHandledInBeginBlock = $false

            if ($null -ne $IncludeUsingVariableName) {
                $lines = @()
                $lines += 'if ($PSSenderInfo) {'
                $IncludeUsingVariableName | ForEach-Object {
                    $lines += '$Script:name=$Using:name'.Replace("name", "$_")
                }
                $lines += "}" + [System.Environment]::NewLine
                $usingLines = $lines -join [System.Environment]::NewLine
            } else {
                $usingLines = [System.Environment]::NewLine
            }

            if ($null -ne $IncludeScriptBlock) {
                $lines = @()
                $IncludeScriptBlock | ForEach-Object {
                    $lines += "Function $($_.Ast.Name) { $([System.Environment]::NewLine)"
                    $lines += "$($_.ToString().Trim()) $([System.Environment]::NewLine) } $([System.Environment]::NewLine)"
                }
                $scriptBlockIncludeLines = $lines -join [System.Environment]::NewLine
            } else {
                $scriptBlockIncludeLines = [System.Environment]::NewLine
            }

            # There are a few different ways to create a script block
            # [ScriptBlock]::Create(string) and ${Function:Write-Verbose}
            # each one ends up adding in the ParamBlock at different locations
            # You need to add in the injected code after the params, if that is the only thing that is passed
            # If you provide a script block that contains a begin or a process section,
            # you need to add the injected code into the begin block.
            # Here you need to find the ParamBlock and add it to the inject lines to be at the top of the script block.
            # Then you need to recreate the adjustedScriptBlock to be where the ParamBlock ended.

            # adjust the location of the adjustedScriptBlock if required here.
            if ($null -ne $PrimaryScriptBlock.Ast.ParamBlock -or
                $null -ne $PrimaryScriptBlock.Ast.Body.ParamBlock) {

                if ($null -ne $PrimaryScriptBlock.Ast.ParamBlock) {
                    Write-Verbose "Ast ParamBlock detected"
                    $adjustLocation = $PrimaryScriptBlock.Ast
                } elseif ($null -ne $PrimaryScriptBlock.Ast.Body.ParamBlock) {
                    Write-Verbose "Ast Body ParamBlock detected"
                    $adjustLocation = $PrimaryScriptBlock.Ast.Body
                } else {
                    throw "Unknown adjustLocation"
                }

                $scriptBlockInjectLines += $adjustLocation.ParamBlock.ToString()
                $startIndex = $adjustLocation.ParamBlock.Extent.EndOffSet - $adjustLocation.Extent.StartOffset
                $adjustedScriptBlock = [ScriptBlock]::Create($PrimaryScriptBlock.ToString().Substring($startIndex))
            }

            # Inject the script blocks and using parameters in the begin block when required.
            if ($null -ne $adjustedScriptBlock.Ast.BeginBlock) {
                Write-Verbose "Ast BeginBlock detected"
                $replaceMatch = $adjustedScriptBlock.Ast.BeginBlock.Extent.ToString()
                $addString = [string]::Empty + [System.Environment]::NewLine
                $addString += {
                    if ($PSSenderInfo) {
                        $VerbosePreference = $Using:VerbosePreference
                        $DebugPreference = $Using:DebugPreference
                    }
                }
                $addString += [System.Environment]::NewLine + $usingLines + $scriptBlockIncludeLines
                $startIndex = $replaceMatch.IndexOf("{")
                #insert the adding context to one character after the begin curl bracket
                $replaceWith = $replaceMatch.Insert($startIndex + 1, $addString)
                $adjustedScriptBlock = [ScriptBlock]::Create($adjustedScriptBlock.ToString().Replace($replaceMatch, $replaceWith))
                $injectedLinesHandledInBeginBlock = $true
            } elseif ($null -ne $adjustedScriptBlock.Ast.ProcessBlock) {
                # Add in a begin block that contains all information that we are wanting.
                Write-Verbose "Ast Process Block detected"
                $addString = [string]::Empty + [System.Environment]::NewLine
                $addString += {
                    begin {
                        if ($PSScriptRoot) {
                            $VerbosePreference = $Using:VerbosePreference
                            $DebugPreference = $Using:DebugPreference
                        }
                    }
                }
                $endIndex = $addString.LastIndexOf("}") - 1
                $addString = $addString.insert($endIndex, [System.Environment]::NewLine + $usingLines + $scriptBlockIncludeLines + [System.Environment]::NewLine )
                $startIndex = $adjustedScriptBlock.Ast.ProcessBlock.Extent.StartOffset - 1
                $adjustedScriptBlock = [ScriptBlock]::Create($adjustedScriptBlock.ToString().Insert($startIndex, $addString))
                $injectedLinesHandledInBeginBlock = $true
            } else {
                Write-Verbose "No Begin or Process Blocks detected, normal injection"
                $scriptBlockInjectLines += {
                    if ($PSSenderInfo) {
                        $VerbosePreference = $Using:VerbosePreference
                        $DebugPreference = $Using:DebugPreference
                    }
                }
            }

            if (-not $injectedLinesHandledInBeginBlock) {
                $scriptBlockInjectLines += $usingLines + $scriptBlockIncludeLines + [System.Environment]::NewLine
            }

            # Combined the injected lines and the main script block together
            # then create a new script block from finalized result
            $scriptBlockInjectLines += $adjustedScriptBlock
            $scriptBlockInjectLines | ForEach-Object {
                $scriptBlockFinalized += $_.ToString() + [System.Environment]::NewLine
            }

            # In order to fully use Invoke-Command, we need to wrap everything in it's own function name again.
            if (-not [string]::IsNullOrEmpty($PrimaryScriptBlock.Ast.Name)) {
                Write-Verbose "Wrapping into function name"
                $scriptBlockFinalized = "function $($PrimaryScriptBlock.Ast.Name) { $([System.Environment]::NewLine)" +
                "$scriptBlockFinalized $([System.Environment]::NewLine) } $([System.Environment]::NewLine) $($PrimaryScriptBlock.Ast.Name) @args"
            }

            return ([ScriptBlock]::Create($scriptBlockFinalized))
        } catch {
            Write-Verbose "Failed to add to the script block"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
}
