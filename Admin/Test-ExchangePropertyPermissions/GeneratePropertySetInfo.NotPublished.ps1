# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$propertySets = @(
    [PSCustomObject]@{
        Name             = "Exchange-Information"
        RightsGuid       = [Guid]::Parse("1F298A89-DE98-47b8-B5CD-572AD53D267E")
        MemberAttributes = New-Object System.Collections.ArrayList
    },
    [PSCustomObject]@{
        Name             = "Exchange-Personal-Information"
        RightsGuid       = [Guid]::Parse("B1B3A417-EC55-4191-B327-B72E33E38AF2")
        MemberAttributes = New-Object System.Collections.ArrayList
    },
    [PSCustomObject]@{
        Name             = "Personal-Information"
        RightsGuid       = [Guid]::Parse("77B5B886-944A-11d1-AEBD-0000F80367C1")
        MemberAttributes = New-Object System.Collections.ArrayList
    },
    [PSCustomObject]@{
        Name             = "Public-Information"
        RightsGuid       = [Guid]::Parse("E48D0154-BCF8-11D1-8702-00C04FB96050")
        MemberAttributes = New-Object System.Collections.ArrayList
    }
)

$rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
$schemaContainer = [ADSI]("LDAP://" + $rootDSE.schemaNamingContext)

foreach ($propertySet in $propertySets) {
    $rightsGuidByteString = ""
    $propertySet.RightsGuid.ToByteArray() | ForEach-Object { $rightsGuidByteString += ("\$($_.ToString("X"))") }
    $searcher = New-Object System.DirectoryServices.directorySearcher($schemaContainer, "(&(objectClass=attributeSchema)(attributeSecurityGuid=$rightsGuidByteString))")
    $searcher.PageSize = 100
    $results = $searcher.FindAll()
    foreach ($result in $results) {
        [void]$propertySet.MemberAttributes.Add($result.Properties["cn"][0])
    }
}

$getPropertySetInfoBuilder = New-Object System.Text.StringBuilder
[void]$getPropertySetInfoBuilder.AppendLine("# Copyright (c) Microsoft Corporation.")
[void]$getPropertySetInfoBuilder.AppendLine("# Licensed under the MIT License.")
[void]$getPropertySetInfoBuilder.AppendLine("")
[void]$getPropertySetInfoBuilder.AppendLine("# This is a generated function. Do not manually modify.")
[void]$getPropertySetInfoBuilder.AppendLine("function Get-PropertySetInfo {")
[void]$getPropertySetInfoBuilder.AppendLine("    [CmdletBinding()]")
[void]$getPropertySetInfoBuilder.AppendLine("    [OutputType([System.Object[]])]")
[void]$getPropertySetInfoBuilder.AppendLine("    param ()")
[void]$getPropertySetInfoBuilder.AppendLine("")
[void]$getPropertySetInfoBuilder.AppendLine("    # cSpell:disable")
[void]$getPropertySetInfoBuilder.AppendLine("    `$propertySetInfo = @(")
for ($i = 0; $i -lt $propertySets.Count; $i++) {
    $propertySet = $propertySets[$i]
    $memberAttributeString = [string]::Join(", ", ($propertySet.MemberAttributes | ForEach-Object { "`"$_`"" }))
    [void]$getPropertySetInfoBuilder.AppendLine("        [PSCustomObject]@{")
    [void]$getPropertySetInfoBuilder.AppendLine("            Name             = `"$($propertySet.Name)`"")
    [void]$getPropertySetInfoBuilder.AppendLine("            RightsGuid       = [Guid]::Parse(`"$($propertySet.RightsGuid)`")")
    [void]$getPropertySetInfoBuilder.AppendLine("            MemberAttributes = $memberAttributeString")
    [void]$getPropertySetInfoBuilder.Append("        }")
    if ($i + 1 -lt $propertySets.Count) {
        [void]$getPropertySetInfoBuilder.AppendLine(",")
    }
}
[void]$getPropertySetInfoBuilder.AppendLine("    )")
[void]$getPropertySetInfoBuilder.AppendLine("    # cSpell:enable")
[void]$getPropertySetInfoBuilder.AppendLine("    `$propertySetInfo")
[void]$getPropertySetInfoBuilder.AppendLine("}")
[void]$getPropertySetInfoBuilder.AppendLine("")

Set-Content $PSScriptRoot\Get-PropertySetInfo.ps1 $getPropertySetInfoBuilder.ToString()
