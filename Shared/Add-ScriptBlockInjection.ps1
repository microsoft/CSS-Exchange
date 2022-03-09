# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1

# Injects Verbose and Debug Preferences and other passed variables into the script block
# It will also inject any additional script blocks into the main script block.
# This allows for an Invoke-Command to work as intended if multiple functions/script blocks are required.
Function Add-ScriptBlockInjection {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$PrimaryScriptBlock,

        [string[]]$IncludeUsingParameter,

        [scriptblock[]]$IncludeScriptBlock,

        [scriptblock]
        $CatchActionFunction
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
            $adjustInject = $false

            if ($null -ne $IncludeUsingParameter) {
                $lines = @()
                $lines += 'if ($PSSenderInfo) {'
                $IncludeUsingParameter | ForEach-Object {
                    $lines += '$name=$Using:name'.Replace("name", "$_")
                }
                $lines += "}" + [System.Environment]::NewLine
                $usingLines = $lines -join [System.Environment]::NewLine
            } else {
                $usingLines = [System.Environment]::NewLine
            }

            if ($null -ne $IncludeScriptBlock) {
                $lines = @()
                $IncludeScriptBlock | ForEach-Object {
                    $lines += $_.Ast.Parent.ToString() + [System.Environment]::NewLine
                }
                $scriptBlockIncludeLines = $lines -join [System.Environment]::NewLine
            } else {
                $scriptBlockIncludeLines = [System.Environment]::NewLine
            }

            # There are a few different ways to create a script block
            # [scriptblock]::Create(string) and ${Function:Write-Verbose}
            # each one ends up adding in the ParamBlock at different locations
            # You need to add in the injected code after the params, if that is the only thing that is passed
            # If you provide a script block that contains a begin or a process section,
            # you need to add the injected code into the begin block.
            # Here you need to find the ParamBlock and add it to the inject lines to be at the top of the script block.
            # Then you need to recreate the adjustedScriptBlock to be where the ParamBlock ended.

            if ($null -ne $PrimaryScriptBlock.Ast.ParamBlock) {
                Write-Verbose "Ast ParamBlock detected"
                $adjustLocation = $PrimaryScriptBlock.Ast
            } elseif ($null -ne $PrimaryScriptBlock.Ast.Body.ParamBlock) {
                Write-Verbose "Ast Body ParamBlock detected"
                $adjustLocation = $PrimaryScriptBlock.Ast.Body
            }

            $adjustInject = $null -ne $PrimaryScriptBlock.Ast.ParamBlock -or $null -ne $PrimaryScriptBlock.Ast.Body.ParamBlock

            if ($adjustInject) {
                $scriptBlockInjectLines += $adjustLocation.ParamBlock.ToString()
                $startIndex = $adjustLocation.ParamBlock.Extent.EndOffSet - $adjustLocation.Extent.StartOffset
                $adjustedScriptBlock = [scriptblock]::Create($PrimaryScriptBlock.ToString().Substring($startIndex))
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
                $adjustedScriptBlock = [scriptblock]::Create($adjustedScriptBlock.ToString().Replace($replaceMatch, $replaceWith))
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
                $adjustedScriptBlock = [scriptblock]::Create($adjustedScriptBlock.ToString().Insert($startIndex, $addString))
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

            #Need to return a string type otherwise run into issues.
            return $scriptBlockFinalized
        } catch {
            Write-Verbose "Failed to add to the script block"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
}
