# Pester Testing Guidelines for CSS-Exchange

This document outlines standards for writing Pester tests in the CSS-Exchange repository. Tests should be runnable both locally (via `.build/Pester.ps1`) and in Azure Pipelines.

---

## Quick Start

### File Naming & Location

- **Test files**: `<ScriptName>.Tests.ps1`
- **Location**: Colocated in `Tests/` subdirectory next to the script being tested
- **Example**:
  ```
  Shared/Tests/Get-ExchangeBuildVersionInformation.Tests.ps1
  Admin/MonitorExchangeAuthCertificate/DataCollection/Tests/Get-ExchangeAuthCertificateStatus.Tests.ps1
  ```

### Basic Test Structure

Every test file should follow this recommended template (some established tests like HealthChecker may differ in structure):

```powershell
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()

BeforeAll {
    # Dot-source the parent script
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\Get-ExchangeAuthCertificateStatus.ps1
    
    # Mock external dependencies
    function Invoke-CatchActionError { param() }
    # ... other mocks ...
}

Describe "Testing Get-ExchangeAuthCertificateStatus.ps1" {
    Context "Scenario 1: Normal Operation" {
        BeforeAll {
            $Script:testData = [PSCustomObject]@{ CurrentCertificateThumbprint = "ABC123" }
            Mock Get-AuthConfig { return $Script:testData }
            $Script:result = Get-ExchangeAuthCertificateStatus
        }
        
        It "Should return expected result" {
            $Script:result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Scenario 2: Error Handling" {
        It "Should handle null input gracefully" {
            { Get-ExchangeAuthCertificateStatus -Identity $null } | Should -Throw
        }
    }
}
```

---

## Test File Requirements

### 1. Header

All test files must include:
```powershell
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
```

### 2. Suppress Known Violations

Test files often need suppressions for PSScriptAnalyzer rules:
```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Pester testing file')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Pester testing file')]
[CmdletBinding()]
param()
```

### 3. BeforeAll Block

Initialize tests once at the start of the file:
```powershell
BeforeAll {
    # 1. Dot-source the parent script
    $Script:parentPath = (Split-Path -Parent $PSScriptRoot)
    . $Script:parentPath\YourScript.ps1
    
    # 2. Dot-source any shared helper scripts
    . $Script:parentPath\Helper.ps1
    
    # 3. Define mock functions
    function Invoke-CatchActionError { param() }
    function Write-HostLog { param([string]$Message) }
    
    # 4. Load test data
    $Script:testData = Import-Clixml "$Script:parentPath\Tests\Data\TestData.xml"
}
```

**Why**: Ensures consistent state for all tests; avoids repeated dot-sourcing.

### 4. Describe & Context Blocks

Organize tests logically:
```powershell
Describe "Testing Get-ServerConfig.ps1" {
    Context "Parameter Validation" {
        # Tests for invalid input handling
    }
    
    Context "Happy Path: Valid Configuration" {
        # Tests for normal operation
    }
    
    Context "Error Handling: API Failures" {
        # Tests for when external services fail
    }
}
```

**Why**: Clear test organization; makes test output readable; identifies gaps.

---

## Mocking Patterns

### Mock External Cmdlets

Always mock cmdlets that require admin privileges or external connectivity:

```powershell
BeforeAll {
    # Mock Get-ExchangeServer (would require Exchange connection)
    function Get-ExchangeServer {
        param([string]$Identity)
        return Import-Clixml "$Script:parentPath\Tests\Data\ExchangeServer.xml"
    }
    
    # Mock Get-ADUser (would require AD connection)
    function Get-ADUser {
        param([string]$Identity)
        return [PSCustomObject]@{
            UserPrincipalName = $Identity
            DistinguishedName = "CN=$Identity,OU=Users,DC=contoso,DC=com"
        }
    }
}
```

### Mock External Functions

If testing a function that calls other functions in the same script, you may need to mock those:

```powershell
BeforeAll {
    # Mock a helper function
    function Get-ConfigValue {
        param([string]$Key)
        return $Script:mockConfig[$Key]
    }
}
```

### Use `-Scope It` for Test-Level Mocks

For mocks that should only apply to a single test:

```powershell
It "Should handle API timeout" {
    Mock Get-MessageTrace { throw "Request timeout" } -Scope It
    { Get-MessageTrace -StartDate (Get-Date) } | Should -Throw
}
```

### Test Data Files

Store complex test data in XML files:

```powershell
# Tests\Data\ExchangeServer.xml
$mockExchangeServer = @(
    [PSCustomObject]@{
        Name = "EX01"
        AdminDisplayVersion = "Version 15.2 (Build 1118.45)"
    },
    [PSCustomObject]@{
        Name = "EX02"
        AdminDisplayVersion = "Version 15.2 (Build 1118.45)"
    }
) | Export-Clixml -Path "Tests\Data\ExchangeServer.xml"
```

Then load in tests:
```powershell
$mockData = Import-Clixml "$Script:parentPath\Tests\Data\ExchangeServer.xml"
```

---

## Writing Effective Test Cases

### 1. Test Valid Input

```powershell
Context "Valid Input" {
    BeforeAll {
        Mock Get-AuthConfig { return $Script:validAuthConfig }
        $Script:results = Get-ExchangeAuthCertificateStatus
    }
    
    It "Should return valid result object" {
        $results | Should -Not -BeNullOrEmpty
    }
    
    It "Should have expected properties" {
        $results.PSObject.Properties.Name | Should -Contain "CurrentAuthCertificateLifetimeInDays"
        $results.PSObject.Properties.Name | Should -Contain "ReplaceRequired"
    }
    
    It "Should have correct data types" {
        $results.ReplaceRequired | Should -BeOfType [bool]
        $results.CurrentAuthCertificateLifetimeInDays | Should -BeOfType [int]
    }
}
```

### 2. Test Edge Cases

```powershell
Context "Edge Cases" {
    It "Should handle null input gracefully" {
        { Get-ExchangeAuthCertificateStatus -Identity $null } | Should -Throw
    }
    
    It "Should handle empty array" {
        Mock Get-ExchangeServer { return @() }
        $results = Get-ExchangeAuthCertificateStatus
        $results.NumberOfUnreachableServers | Should -Be 0
    }
    
    It "Should handle certificate expiration today" {
        Mock Get-Date { return [DateTime]::Parse('2024-12-31T00:00:00') }
        $cert = New-AuthCertificateUnitTestObject -NotAfter '2024-12-31T23:59:59'
        $results = Test-CertificateExpiration -Certificate $cert
        $results.DaysUntilExpiration | Should -Be 0
    }
}
```

### 3. Test Error Paths

```powershell
Context "Error Handling" {
    It "Should throw when Exchange is unreachable" {
        Mock Get-ExchangeServer { throw "Cannot connect to remote Exchange server" }
        { Get-ExchangeAuthCertificateStatus } | Should -Throw
    }
    
    It "Should catch and handle cmdlet errors gracefully" {
        Mock Get-AuthConfig { throw "Access denied" }
        # Function should not crash; should return error status
        { Get-ExchangeAuthCertificateStatus -ErrorAction Stop } | Should -Throw
    }
    
    It "Should continue with partial results if one server fails" {
        Mock Get-ExchangeServer {
            return @(
                [PSCustomObject]@{ Name = "EX01" },
                [PSCustomObject]@{ Name = "EX02" }
            )
        }
        Mock Test-SingleServerHealth { 
            param([string]$Server)
            if ($Server -eq "EX02") { throw "Error" }
            return [PSCustomObject]@{ Server = $Server; Status = "OK" }
        } -Scope It
        
        $results = Get-ExchangeAuthCertificateStatus
        $results | Should -HaveCount 1
        $results[0].Server | Should -Be "EX01"
    }
}
```

### 4. Test Business Logic

```powershell
Context "Certificate Lifecycle Logic" {
    BeforeAll {
        Mock Get-Date { return [DateTime]::Parse('2023-01-01T00:00:00') }
    }
    
    It "Should mark certificate as valid when > 180 days" {
        $cert = New-AuthCertificateUnitTestObject -NotAfter '2024-01-01'
        ($cert.NotAfter - (Get-Date)).Days | Should -BeGreaterThan 180
    }
    
    It "Should mark certificate as requiring replacement when < 60 days" {
        $cert = New-AuthCertificateUnitTestObject -NotAfter '2023-02-01'
        $result = Test-CertificateExpiration -Certificate $cert
        $result.ReplaceRequired | Should -Be $true
    }
    
    It "Should correctly order certificates by expiration date" {
        $certs = @(
            (New-AuthCertificateUnitTestObject -NotAfter '2024-12-31'),
            (New-AuthCertificateUnitTestObject -NotAfter '2023-06-30'),
            (New-AuthCertificateUnitTestObject -NotAfter '2025-01-01')
        )
        $sorted = $certs | Sort-Object NotAfter
        $sorted[0].NotAfter | Should -Be '2023-06-30'
        $sorted[-1].NotAfter | Should -Be '2025-01-01'
    }
}
```

---

## Coverage Requirements

### Minimum Coverage by Function Type

| Function Type | Min Coverage | Why |
|---------------|--------------|-----|
| **Public API** | 100% | Users depend on documented behavior |
| **Private Helper** | 80%+ | Internal logic; some edge cases OK |
| **Validation Logic** | 100% | Security/correctness-critical |
| **Error Handling** | 90%+ | Must be reliable under failures |
| **Exchange-Specific** | 100% | API misuse causes production issues |
| **Graph API Integration** | 100% (mock) | API changes cause service disruption |

### Coverage Guidance

**DO test**:
- ✅ All public function parameters and combinations
- ✅ Error paths (what happens when API fails, input invalid, etc.)
- ✅ Edge cases (null, empty, single item, large dataset)
- ✅ Business logic (dates, calculations, comparisons)
- ✅ Type validation (correct data types returned)
- ✅ Exchange-specific cmdlets (Get-ExchangeServer, Get-MessageTrace, etc.)

**DON'T test** (mock instead):
- ❌ External API calls (Exchange Online, Graph, AD) — mock them
- ❌ File I/O operations — mock file functions
- ❌ Network calls — mock network functions
- ❌ Tenant-specific data — use mocked/sanitized test data

### Code Coverage Example

If a function has 10 branches, you should test:
```
Branch 1 (valid input, success) ✅
Branch 2 (null input) ✅
Branch 3 (empty array) ✅
Branch 4 (API error) ✅
Branch 5 (permission denied) ✅
Branch 6 (timeout) ✅
Branch 7 (malformed data) ✅
Branch 8 (single item) ✅
Branch 9 (multiple items) ✅
Branch 10 (boundary condition) ✅

Coverage: 10/10 (100%)
```

---

## Assertion Best Practices

### Use Proper Pester Assertions

❌ **Bad** (hard to read, unclear failure messages):
```powershell
if ($result -eq $null) { throw "Expected non-null result" }
if ($result.Count -ne 5) { throw "Expected 5 items" }
if ($result.Name -notlike "Exchange*") { throw "Name doesn't match" }
```

✅ **Good** (clear, self-documenting):
```powershell
$result | Should -Not -BeNullOrEmpty
$result | Should -HaveCount 5
$result.Name | Should -Match "^Exchange"
```

### Common Assertions

```powershell
# Equality
$result | Should -Be $expected
$result | Should -Not -Be $expected

# Null checks
$result | Should -BeNullOrEmpty
$result | Should -Not -BeNullOrEmpty

# Collections
$result | Should -HaveCount 5
$result | Should -Contain $item

# Comparisons
$value | Should -BeGreaterThan 100
$value | Should -BeLessThanOrEqual 1000

# Type checks
$result | Should -BeOfType [int]
$result | Should -BeOfType [PSCustomObject]

# String matching
$message | Should -Match "pattern"
$message | Should -MatchExactly "exact match"
$message | Should -Like "wild*card"

# Exceptions
{ Invoke-Command } | Should -Throw
{ Invoke-Command } | Should -Throw -ExceptionType [ArgumentException]

# Collections
$results | Should -HaveCount 3
$results.Name | Should -Contain "ItemA"
$results | Should -BeEmpty
```

---

## Running Tests

### Local Execution

Run all tests:
```powershell
.build/Pester.ps1
```

Run tests for specific files changed on main branch:
```powershell
.build/Pester.ps1 -Branch main
```

Run specific test file directly with Pester:
```powershell
Invoke-Pester -Path "Admin/MonitorExchangeAuthCertificate/DataCollection/Tests/Get-ExchangeAuthCertificateStatus.Tests.ps1"
```

### Azure Pipeline Execution

Tests run automatically on PR and push to main. Configuration in `.github/workflows/` or pipeline files. Environment setup handles:
- ✅ PowerShell 7+ installation
- ✅ Pester module installation
- ✅ No actual Exchange/AD/Graph connections (all mocked)
- ✅ No credential/tenant data exposure

---

## Common Issues & Solutions

### Issue: "Cannot find path to parent script"

**Cause**: Incorrect $PSScriptRoot usage
```powershell
# Wrong:
. $PSScriptRoot\..\Get-ExchangeServerCertificate.ps1

# Right:
$Script:parentPath = (Split-Path -Parent $PSScriptRoot)
. $Script:parentPath\Get-ExchangeServerCertificate.ps1
```

### Issue: "Mock not being used"

**Cause**: Function dot-sourced after mock defined
```powershell
# Wrong:
BeforeAll {
    Mock Get-Date { return [DateTime]::Parse('2023-01-01') }
    . $Script:parentPath\Script.ps1  # Script.ps1 now has Get-Date reference
}

# Right:
BeforeAll {
    . $Script:parentPath\Script.ps1  # Dot-source first
    Mock Get-Date { return [DateTime]::Parse('2023-01-01') }  # Mock after
}
```

### Issue: "Test passes locally but fails in pipeline"

**Cause**: Timezone, date, or system-specific assumptions
```powershell
# Wrong (assumes current year):
$tomorrow = (Get-Date).AddDays(1)

# Right (uses mocked/fixed date):
Mock Get-Date { return [DateTime]::Parse('2023-01-01T00:00:00') }
$tomorrow = (Get-Date).AddDays(1)
$tomorrow | Should -Be ([DateTime]::Parse('2023-01-02T00:00:00'))
```

### Issue: "Tests are slow"

**Cause**: Not using BeforeAll blocks; redundant mocks
```powershell
# Wrong (set up mocks for each test):
It "Test 1" {
    Mock Get-ExchangeServer { return $mockData }
    $result = Get-ExchangeServer
    $result.Count | Should -Be 3
}

It "Test 2" {
    Mock Get-ExchangeServer { return $mockData }  # Repeated
    $result = Get-ExchangeServer
    $result[0].Name | Should -Be "EX01"
}

# Right (set up once):
BeforeAll {
    Mock Get-ExchangeServer { return $mockData }
}

It "Test 1" {
    $result = Get-ExchangeServer
    $result.Count | Should -Be 3
}

It "Test 2" {
    $result = Get-ExchangeServer
    $result[0].Name | Should -Be "EX01"
}
```

---

## Checklist for New Tests

- [ ] Test file is named `<ScriptName>.Tests.ps1`
- [ ] Test file is in `Tests/` subdirectory next to script
- [ ] Copyright header and suppressions included
- [ ] Parent script dot-sourced in `BeforeAll`
- [ ] All external cmdlets are mocked (no real API calls)
- [ ] Tests cover happy path (valid input, success)
- [ ] Tests cover edge cases (null, empty, boundary values)
- [ ] Tests cover error paths (API failures, permission denied, etc.)
- [ ] All assertions use Pester assertions (Should, not if/throw)
- [ ] Test runs locally: `.build/Pester.ps1`
- [ ] Test names describe what is being tested
- [ ] No hardcoded dates (mock `Get-Date`)
- [ ] No tenant/subscription-specific data in test fixtures
- [ ] Test data files in `Tests/Data/` are sanitized (no real credentials)

---

## References

- **Pester Documentation**: https://pester.dev/
- **PSScriptAnalyzer Rules**: https://github.com/PowerShell/PSScriptAnalyzer/
- **PowerShell Best Practices**: https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines
- **Approved PowerShell Verbs**: https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.5

