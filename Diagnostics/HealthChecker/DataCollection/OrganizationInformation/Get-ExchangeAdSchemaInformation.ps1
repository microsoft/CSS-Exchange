﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-ExchangeAdSchemaClass.ps1
. $PSScriptRoot\..\..\..\..\Shared\ScriptBlockFunctions\RemotePipelineHandlerFunctions.ps1

function Get-ExchangeAdSchemaInformation {

    process {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnObject = New-Object PSCustomObject
        $schemaClasses = @("ms-Exch-Storage-Group", "ms-Exch-Schema-Version-Pt")

        foreach ($name in $schemaClasses) {
            $propertyName = $name.Replace("-", "")
            $value = $null
            try {
                Get-ExchangeAdSchemaClass -SchemaClassName $name | Invoke-RemotePipelineHandler -Result ([ref]$value)
            } catch {
                Write-Verbose "Failed to get $name"
                Invoke-CatchActions
            }
            $returnObject | Add-Member -MemberType NoteProperty -Name $propertyName -Value $value
        }
    } end {
        return $returnObject
    }
}
