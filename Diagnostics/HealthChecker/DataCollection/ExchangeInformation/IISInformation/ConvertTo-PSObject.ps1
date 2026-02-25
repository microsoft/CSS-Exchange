# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

<#
.DESCRIPTION
    This function converts specific .NET or PowerShell objects into a custom PSCustomObject instance.
    By copying selected properties onto a simple PSCustomObject, it helps avoid serialization
    problems that can occur when remoting or persisting complex framework types.
#>
function ConvertTo-PSObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ObjectToConvert,

        [Parameter(Mandatory = $true)]
        [string[]]$ObjectTypeToConvert,

        [string[]]$PropertiesToSkip,

        [int]$DefaultDepthValue = 5
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        if ((Get-PSCallStack)[1].Command -ne "ConvertTo-PSObject") {
            $Script:ConvertToPSObjectDepth = 0
        }
        $newPSObject = New-Object PSCustomObject
    }
    process {
        # The properties on the object that we want to pull out and place on a custom PS Object.
        # This should help with serialization issues.
        $objectGetTypeFullName = $ObjectToConvert.GetType().FullName
        $doNotConvert = $true

        foreach ($type in $ObjectTypeToConvert) {
            # This is intended to handle both ways that the wildcard can be setup and used.
            if ($type -like $objectGetTypeFullName -or
                $objectGetTypeFullName -like $type) {
                $doNotConvert = $false
            }
        }

        # $Pester should only be set when we are doing Pester testing.
        if ($doNotConvert -and
            $Script:Pester -eq $false) {
            Write-Verbose "Object '$($ObjectToConvert.GetType().FullName)' is not one of these types to convert: $([string]::Join(", ", $ObjectTypeToConvert))."
            return
        }

        $properties = ($ObjectToConvert |
                Get-Member |
                Where-Object {
                    $_.MemberType -ne "Method" -and
                    $_.MemberType -ne "ParameterizedProperty" -and
                    $_.MemberType -ne "CodeMethod" -and
                    $_.MemberType -ne "ScriptMethod"
                }).Name |
                Where-Object { $PropertiesToSkip -notcontains $_ }
        Write-Verbose "Going to include the following properties to the object: $([string]::Join(", ", $properties))"

        foreach ($prop in $properties) {
            # If the property is an array, we need to handle this differently.
            # If the property is one of the types, Call this function again. Otherwise, add it as is.
            if ($ObjectToConvert.$prop -is [array]) {
                Write-Verbose "$prop is an Array on this object."
                $list = New-Object System.Collections.Generic.List[object]

                foreach ($entry in $ObjectToConvert.$prop) {
                    if ($null -ne $entry) {
                        # Make this easier by just calling the method again, just need to add the type object that it is, just in case we are dealing with a list of a different type.
                        $Script:ConvertToPSObjectDepth++
                        $value = $null
                        $params = @{
                            ObjectToConvert     = $entry
                            ObjectTypeToConvert = $ObjectTypeToConvert + ($entry.GetType().FullName)
                            PropertiesToSkip    = $PropertiesToSkip
                            DefaultDepthValue   = $DefaultDepthValue
                        }
                        ConvertTo-PSObject @params | Invoke-RemotePipelineHandler -Result ([ref]$value)
                        $list.Add($value)
                    } else {
                        # Add the empty list.
                        $list.Add($entry)
                    }
                }

                $newPSObject | Add-Member -MemberType NoteProperty -Name $prop -Value $list
            } elseif ($null -ne $ObjectToConvert.$prop -and
                [string]::Empty -ne $ObjectToConvert.$prop -and
                $null -ne ($ObjectTypeToConvert | Where-Object { $ObjectToConvert.$prop.GetType().FullName -like $_ })) {

                if ($Script:ConvertToPSObjectDepth -gt $DefaultDepthValue) {
                    Write-Verbose "Unable to convert this attribute property, as we are too deep in the object."
                    $newPSObject | Add-Member -MemberType NoteProperty -Name $prop -Value "--ERROR TOO DEEP--"
                } else {
                    Write-Verbose "Going to call ConvertTo-PSObject for $prop property to expand"
                    $Script:ConvertToPSObjectDepth++
                    $value = $null
                    $params = @{
                        ObjectToConvert     = ($ObjectToConvert.$prop)
                        ObjectTypeToConvert = $ObjectTypeToConvert
                        PropertiesToSkip    = $PropertiesToSkip
                        DefaultDepthValue   = $DefaultDepthValue
                    }
                    ConvertTo-PSObject @params | Invoke-RemotePipelineHandler -Result ([ref]$value)
                    $newPSObject | Add-Member -MemberType NoteProperty -Name $prop -Value $value
                }
            } else {
                Write-Verbose "Adding property: $prop"
                $newPSObject | Add-Member -MemberType NoteProperty -Name $prop -Value ($ObjectToConvert.$prop)
            }
        }
    }
    end {
        $Script:ConvertToPSObjectDepth--
        return $newPSObject
    }
}
