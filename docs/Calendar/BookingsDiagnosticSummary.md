# BookingsDiagnosticSummary

Download the latest release: [BookingsDiagnosticSummary.ps1](https://aka.ms/BookingsDiagnosticSummary)

This script runs a series of tests in a bookings Mailbox (one per execution) and returns a summarized list of the bookings Mailbox characteristics, as well as testing for known configuration issues that can lead to bookings not performing as expected.

This script only runs on Exchange Online, as Microsoft Bookings is an online only application.

Additionally, it will collect the most common logs needed for troubleshooting by support, including:

* Staff Membership log
* Message Tracking Log
* Booking Mailbox configuration
* Staff List and Permissions
* Services configuration

To run the script, you will need a valid SMTP Address for a booking Mailbox.

The Identity parameter is required, all remaining are optional and default to true.


## Syntax

```powershell
BookingsDiagnosticSummary.ps1 -Identity <string>
  [-Staff <bool>]
  [-StaffMembershipLog <bool>]
  [-Graph <bool>]
  [-MessageTrace <bool>]
  [-ExportToCSV <bool>]
  [-ExportToExcel <bool>]
```


| Parameters:                   | Explanation:                                                                                                                                                                                                                                                                                                                                                                    |
| :---------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **-Identity**           | Booking MB SMTP Address (Only one per execution)                                                                                                                                                                                                                                                                                                                                |
| **-Staff**              | Verify Staff permissions for the Bookings mailbox.                                                                                                                                                                                                                                                                                                                              |
| **-StaffMemberShipLog** | Get the Staff Membership Log for the Bookings mailbox.                                                                                                                                                                                                                                                                                                                          |
| **-Graph**              | Use Graph API to get the Bookings mailbox, Staff, Services and Availability.<br />Graph will allow the best comprehensive tests going through, as it will collect services data and staff, allowing to check more issues, such as permissions and more.<br />In the graph connection you will need the following scopes (Delegated):<br />User.Read.All<br />Bookings.Read.All |
| **-MessageTrace**       | Get MessageTrace logs for the Bookings mailbox(Past 5 days).                                                                                                                                                                                                                                                                                                                    |
| **-ExportToCSV**        | Export all data to CSV.                                                                                                                                                                                                                                                                                                                                                         |
| **-ExportToExcel**      | Export the output to an Excel file with formatting.                                                                                                                                                                                                                                                                                                                             |

---

#### Examples:

Example to perform all tests on a Bookings Mailbox:

```PowerShell
BookingsDiagnosticSummary.ps1 -Identity booking@contoso.com
```

Example to perform tests without collecting Message Traces:

```PowerShell
BookingsDiagnosticSummary.ps1 -Identity booking@contoso.com -MessageTrace $false
```

Export test results to Excel, but skip CSV files creation:

```PowerShell
BookingsDiagnosticSummary.ps1 -Identity booking@contoso.com -ExportCSV $false
```

Will create file like  `.\BookingsSummary_<BookingSMTP>_yyyy-MM-dd_HHmm.xlsx` in current directory.
`<BookingSMTP>` will be the left part of the @ from the email. I.e. booking@contoso.com returns booking.
