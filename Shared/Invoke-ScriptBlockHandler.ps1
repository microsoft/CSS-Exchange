# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Invoke-CatchActionError.ps1

# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
# Adds ability to use Write-Verbose and Write-Debug properly within the remote Script Block
# You can also easily inject other script blocks into the main remote script block.
# Common use to inject is for an override of Write-Verbose if there is a custom override of this function
Function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [scriptblock[]]
        $IncludeScriptBlock,

        [string[]]
        $IncludeUsingParameter,

        [scriptblock]
        $CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null

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
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                # In Remote Execution if you want Write-Verbose to work or add in additional
                # Script Blocks to your code to be executed, like a custom Write-Verbose, you need to inject it into the script block
                # that is passed to Invoke-Command.
                $scriptBlockInjectLines = @()
                $scriptBlockFinalized = [string]::Empty
                $adjustedScriptBlock = $ScriptBlock
                $injectedLinesHandledInBeginBlock = $false
                $adjustInject = $false

                # There are a few different ways to create a script block
                # [scriptblock]::Create(string) and ${Function:Write-Verbose}
                # each one ends up adding in the ParamBlock at different locations
                # You need to add in the injected code after the params, if that is the only thing that is passed
                # If you provide a script block that contains a begin or a process section,
                # you need to add the injected code into the begin block.
                # Here you need to find the ParamBlock and add it to the inject lines to be at the top of the script block.
                # Then you need to recreate the adjustedScriptBlock to be where the ParamBlock ended.

                if ($null -ne $ScriptBlock.Ast.ParamBlock) {
                    Write-Verbose "Ast ParamBlock detected"
                    $adjustLocation = $ScriptBlock.Ast
                } elseif ($null -ne $ScriptBlock.Ast.Body.ParamBlock) {
                    Write-Verbose "Ast Body ParamBlock detected"
                    $adjustLocation = $ScriptBlock.Ast.Body
                }

                $adjustInject = $null -ne $ScriptBlock.Ast.ParamBlock -or $null -ne $ScriptBlock.Ast.Body.ParamBlock

                if ($adjustInject) {
                    $scriptBlockInjectLines += $adjustLocation.ParamBlock.ToString()
                    $startIndex = $adjustLocation.ParamBlock.Extent.EndOffSet - $adjustLocation.Extent.StartOffset
                    $adjustedScriptBlock = [scriptblock]::Create($ScriptBlock.ToString().Substring($startIndex))
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

                $ScriptBlock = [scriptblock]::Create($scriptBlockFinalized)
                Write-Verbose "Created the new script block"

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Stop"
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose "Including SessionOption"
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Invoke-Command with argument list"
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose "Running Invoke-Command without argument list"
                }

                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"
                    $returnValue = & $ScriptBlock $ArgumentList
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            Write-Debug "Caught error in $($MyInvocation.MyCommand)"
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}
