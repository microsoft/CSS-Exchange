# Example Test Scripts Reference

This folder contains minimal example scripts and tests for reference when assisting developers with Pester testing patterns.

**DO NOT** include these in production builds or releases.

> **Note:** These example scripts and tests are intentionally colocated in the same directory for simplicity. Production test files should follow the repo convention of placing tests in a `Tests/` subfolder adjacent to the script being tested.

## Files

### Pattern 1: Basic Getter with Validation
- **Get-ServerConfig.ps1** — Simple function with parameter validation and error handling
- **Get-ServerConfig.Tests.ps1** — Shows testing patterns for:
  - Happy path (valid input, normal operation)
  - Parameter validation (null, empty, range checks)
  - Error handling
  - Edge cases
  - Output validation

**Use when teaching**: "How do I test parameter validation?" or "Show me a happy path + error path example"

---

### Pattern 2: Functions Calling Exchange Cmdlets
- **Test-ServerHealth.ps1** — Example that calls Get-ExchangeServer (mocked)
- **Test-ServerHealth.Tests.ps1** — Shows testing patterns for:
  - Mocking Exchange cmdlets
  - Working with Exchange data structures
  - Date/time handling in tests
  - Certificate/expiration scenarios

**Use when teaching**: "How do I mock Exchange cmdlets?" or "Show me how to test a function that calls Get-ExchangeServer"

---

### Pattern 3: State-Changing Functions
- **Update-ServerSetting.ps1** — Example function that modifies state with validation
- **Update-ServerSetting.Tests.ps1** — Shows testing patterns for:
  - Business logic validation (e.g., memory format rules)
  - Multiple parameter scenarios
  - Testing error messages
  - State change results

**Use when teaching**: "How do I test a function that validates input?" or "Show me how to test format validation"

---

## Key Patterns Demonstrated

| Pattern | Location | Reference |
|---------|----------|-----------|
| Basic parameter validation | Get-ServerConfig.Tests.ps1 lines 55-72 | "Show this to test null/empty checks" |
| Valid/invalid combinations | Update-ServerSetting.Tests.ps1 lines 62-86 | "Show this for format validation" |
| Mocking external cmdlets | Test-ServerHealth.Tests.ps1 lines 26-46 | "Show this to mock Get-ExchangeServer" |
| Error path testing | Get-ServerConfig.Tests.ps1 lines 75-84 | "Show this for error handling tests" |
| Edge cases | Get-ServerConfig.Tests.ps1 lines 87-103 | "Show this for boundary testing" |
| Output validation | Get-ServerConfig.Tests.ps1 lines 105-118 | "Show this for asserting output structure" |

---

## How to Use These Examples

When assisting a developer:

1. **Identify what they need to test** (parameter validation, error handling, etc.)
2. **Reference the appropriate example** by file and line numbers
3. **Copy the pattern** and adapt it to their function
4. **Point out the key assertions** they need

Example dialogue:
> **Dev**: "How do I test that my function rejects null input?"
>
> **You**: "See `Get-ServerConfig.Tests.ps1` lines 56-57. Copy that pattern and replace the function name and parameter."

---

## Important Notes

- These examples are **self-contained** and do **not** call external services
- All external dependencies are **mocked** in the test files
- These are **not** production code — they're teaching templates
- The `.github/` directory is **excluded** from build scripts, so these won't interfere with builds

---

## Reference Documentation

For comprehensive guidelines, see [`.github/pester-testing-guidelines.md`](../pester-testing-guidelines.md)
