#cspell:words aspf, adkim, CTRY

# Email Authentication Checker (CSS Exchange)

## Overview

The Email Authentication Checker is a PowerShell tool designed for analyzing email authentication configurations for domains. It provides detailed validation of SPF, DKIM, and DMARC records with enhanced security analysis and professional HTML reporting.

## Features

### Core Capabilities
- **19 Comprehensive Security Checks** across SPF, DKIM, and DMARC protocols
- **Professional HTML Reports** with interactive visualizations and charts
- **Provider-Aware Documentation** with direct links to Microsoft or industry documentation
- **Authoritative DNS Queries** for accurate TTL validation and record retrieval
- **Email Header Analysis** for real-world authentication result evaluation

### Analysis Modes
1. **Multiple Domain Analysis** - Analyze one or multiple domains (comma-separated)
2. **File-Based Analysis** - Load domains from a text file (one per line)
3. **Email Header Analysis** - Extract and analyze domains from email headers

### Security Checks

#### SPF (9 Checks)
- Record presence validation
- Syntax validation and compliance
- Single record compliance (RFC 7208)
- DNS lookup count validation (max 10)
- Record length validation (max 255 chars)
- TTL analysis for optimization
- SPF enforcement rule analysis (`all` mechanism)
- Macro security assessment
- Sub-record TTL validation (A/MX/TXT records)

#### DMARC (5 Checks)
- Record presence validation
- Policy assessment (none/quarantine/reject)
- Reporting configuration validation (rua/ruf)
- Alignment modes validation (aspf/adkim)
- TTL validation for performance

#### DKIM (5 Checks)
- Selector discovery and validation
- Syntax validation and compliance
- Key status analysis (active/revoked/testing)
- Key strength assessment (bit length)
- TTL validation for reliability

## Requirements

### Prerequisites
- **PowerShell 5.1** or later
- **Windows** operating system
- **Internet connectivity** for DNS queries
- **Administrator privileges** (recommended for optimal DNS resolution)

### Dependencies
- Built-in PowerShell modules (no external dependencies required)
- Uses native Windows DNS resolution capabilities

## Usage

### Basic Syntax
```powershell
.\EmailAuthChecker.ps1 [parameters]
```

### Parameters

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `-DomainList` | String | Domains to analyze (comma-separated) | No |
| `-FilePath` | String | Path to file containing domains (one per line) | No |
| `-HeaderFilePath` | String | Path to file containing email headers | No |
| `-OutputPath` | String | Directory for HTML report (default: current directory) | No |
| `-AutoOpen` | Switch | Automatically open report in browser | No |

### Usage Examples

#### Single Domain Analysis
```powershell
.\EmailAuthChecker.ps1 -DomainList microsoft.com
```

#### Multiple Domain Analysis
```powershell
.\EmailAuthChecker.ps1 -DomainList microsoft.com, contoso.com, outlook.com
```

#### File-Based Analysis
```powershell
.\EmailAuthChecker.ps1 -FilePath "C:\temp\domains.txt" -OutputPath "C:\reports" -AutoOpen
```

#### Email Header Analysis
```powershell
.\EmailAuthChecker.ps1 -HeaderFilePath "C:\temp\headers.txt"
```

#### Custom Output with Auto-Open
```powershell
.\EmailAuthChecker.ps1 -Domain "example.com" -OutputPath "C:\EmailReports" -AutoOpen
```

## Email Header Analysis

### Supported Header Analysis
The script can parse and analyze the following email headers:

#### Authentication-Results Headers
- **SPF Results** - Pass/Fail/SoftFail/Neutral/None/PermError/TempError
- **DKIM Results** - Pass/Fail/None/Policy/Neutral/TempError/PermError
- **DMARC Results** - Pass/Fail/None with detailed condition analysis

#### Microsoft-Specific Headers
- **X-Microsoft-Antispam-Mailbox-Delivery**
  - UCF (Unified Content Filter) status
  - JMR (Junk Mail Rule) application
  - Dest (Destination) routing information
  - OFR (Organizational Filtering Rules) status

- **X-MS-Office365-Filtering-Correlation-Id**
  - Correlation ID for tracking through Microsoft systems

- **X-Forefront-Antispam-Report-Untrusted**
  - CIP (Client IP) address
  - CTRY (Country) of origin
  - LANG (Language) detection
  - SCL (Spam Confidence Level)
  - SRV (Service) classification
  - IPV (IP Version) - IPv4/IPv6
  - SFV (Sender Filter Verdict)
  - PTR (Reverse DNS) validation
  - CAT (Category) classification
  - DIR (Direction) - inbound/outbound
  - SFP (Sender Filter Policy) applied

### Domain Extraction
- Extracts domains from `smtp.mailfrom` fields
- Extracts domains from `header.from` fields
- Validates and cleans extracted domains
- Performs comprehensive analysis on extracted domains

## Output & Reporting

### HTML Report Features
- **Interactive Dashboard** with domain scores and status indicators
- **Protocol-Specific Sections** for SPF, DKIM, and DMARC analysis
- **Visual Charts** showing check results and recommendations
- **Provider-Aware Documentation Links** based on detected email providers
- **Email Header Analysis Section** (when using HeaderFilePath)
- **Responsive Design** for desktop and mobile viewing
- **Professional Styling** with modern CSS and interactive elements

### Report Sections
1. **Executive Summary** - Overall domain health and scores
2. **SPF Analysis** - Detailed SPF record evaluation
3. **DKIM Analysis** - DKIM selector and key analysis
4. **DMARC Analysis** - Policy and configuration assessment
5. **Email Header Analysis** - Real-world authentication results (when applicable)
6. **Recommendations** - Actionable security improvements
7. **Technical Details** - Raw records and technical specifications

### Security Analysis

#### Risk Assessment
- **Critical Issues** - Missing records, syntax errors, security vulnerabilities
- **Warning Issues** - Suboptimal configurations, performance concerns
- **Informational Items** - Best practice recommendations, optimization opportunities

#### Provider Detection
- Automatically detects email providers based on MX records
- Provides provider-specific documentation and recommendations
- Supports Microsoft/Office 365, Google/Gmail, Amazon SES, and others

## Advanced Features

### Authoritative DNS Queries
- Queries authoritative DNS servers directly for accurate results
- Bypasses DNS caching issues that can affect analysis accuracy
- Provides real TTL values from authoritative sources

### TTL Analysis
- Analyzes TTL values for SPF, DKIM, and DMARC records
- Identifies suboptimal TTL settings that impact performance
- Provides recommendations for TTL optimization

### Macro Security Analysis
- Evaluates SPF macros for potential security risks
- Identifies complex macros that may expose infrastructure
- Warns about macros that could be used for data exfiltration

### Multi-Provider Support
- Supports analysis across different email service providers
- Provides provider-specific recommendations and documentation
- Handles provider-specific record formats and requirements

## Error Handling & Validation

### Input Validation
- Domain format validation with context-specific rules
- File existence and accessibility checks
- Parameter set validation to prevent conflicting inputs

### DNS Error Handling
- Graceful handling of DNS resolution failures
- Timeout management for slow DNS responses
- Fallback mechanisms for unreachable authoritative servers

### Output Validation
- HTML sanitization to prevent injection attacks
- Path validation for output directory creation
- File permission checks for report generation

## Performance Considerations

### Optimization Features
- Efficient DNS query batching
- Parallel processing where applicable
- Caching of DNS responses within session
- Optimized regular expressions for header parsing

### Resource Management
- Memory-efficient processing of large domain lists
- Cleanup of temporary variables and objects
- Controlled execution time with appropriate timeouts

## Security Considerations

### Script Security
- No external dependencies or downloads
- Uses only built-in PowerShell capabilities
- Input sanitization and validation
- No persistent storage of sensitive data

### Analysis Security
- Identifies security vulnerabilities in email authentication
- Provides actionable remediation steps
- Warns about configuration risks and exposures

## Troubleshooting

### Common Issues

#### DNS Resolution Problems
- **Symptoms**: "No authoritative servers found" errors
- **Solutions**: Check network connectivity, try different DNS servers, verify domain existence

#### File Access Issues
- **Symptoms**: "Access denied" or "File not found" errors
- **Solutions**: Verify file paths, check permissions, ensure files exist

#### Large Domain Lists
- **Symptoms**: Slow performance or timeouts
- **Solutions**: Process domains in smaller batches, increase timeout values

### Debugging Options
- Use `-Verbose` parameter for detailed operation logging
- Check DNS resolution manually with `nslookup` or `Resolve-DnsName`
- Validate input files for proper formatting and encoding

## License & Disclaimer

### Disclaimer
This script has been thoroughly tested across various environments and scenarios. However, by using this script, you acknowledge and agree that:

1. You are responsible for how you use the script and any outcomes resulting from its execution
2. The entire risk arising out of the use or performance of the script remains with you
3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks

## Support & Contribution

### Getting Help
- Use `Get-Help .\EmailAuthChecker.ps1 -Full` for detailed parameter information
- Review the generated HTML reports for analysis explanations
- Check the troubleshooting section for common issues

### Best Practices
- Run with administrator privileges for optimal DNS resolution
- Test with known good domains first to verify functionality
- Use the AutoOpen feature for immediate report review
- Save reports with descriptive names including dates/times
- Review recommendations carefully before implementing changes

## Version History

### v1.5 Enhanced (Current)
- Enhanced email header analysis capabilities
- Improved provider-specific documentation integration
- Advanced TTL analysis and optimization recommendations
- Comprehensive Microsoft antispam header parsing
- Modern HTML report design with interactive elements
- Parameter-only operation mode for automation
- Enhanced security analysis and risk assessment

---

*This documentation covers the comprehensive email authentication analysis capabilities of the EmailAuthChecker.ps1 script. For the most current information and updates, refer to the script's built-in help documentation using the PowerShell Get-Help cmdlet.*
