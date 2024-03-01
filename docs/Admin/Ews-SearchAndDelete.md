Ews-SearchAndDelete

This PowerShell script can be used to search and delete content from a mailbox using EWS. The search can be performed using the sender email address, subject, created/received time, recipient, or message body. The search can be executed against either the primary or archive mailbox.

Requirements
An application registration must be created in Azure AD for the tenant and this application must have the full_access_as_app API permission for EWS. The script also required the EWS Managed API (the DLL file can be download and saved in the same directory as the script).

How To Run
This syntax will search the Inbox for items from a sender with the email address kelly@contoso.com and generate a CSV file with the results.

.\Ews-SearchAndDelete.ps1 -Mailbox jim@contoso.com -Sender kelly@contoso.com -ResultsFile C:\Temp\jimResults.csv -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthSecretKey qau8Q~5L23ScrpM3b2tcd -IncludeFolderList Inbox

This syntax will search the entire mailbox from items where the subject contains the word Microsoft and the message body contains the word Exchange, generate a CSV file with the results, and delete the items.

.\Ews-SearchAndDelete.ps1 -Mailbox jim@contoso.com -Subject Microsoft -ResultsFile C:\Temp\JimResults.csv -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthSecretKey qau8Q~5L23ScrpM3b2tcd -ProcessSubfolders -MessageBody Exchange -DeleteContent

This syntax will search the Recoverable Items for items created between 01 Jan 2024 and 31 Jan 2024, generate a CSV file with the results, and hard delete the items.

.\Ews-SearchAndDelete.ps1 -Mailbox jim@contoso.com -Archive -ResultsFile C:\Temp\JimResults.csv -OAuthClientId 2e542266-a1b2-4567-8901-abcdccd61976 -OAuthTenantId 9101fc97-a2e6-2255-a2d5-83e051e52057 -OAuthSecretKey qau8Q~5L23ScrpM3b2tcd -SearchDumpster -HardDelete -CreatedBefore '2024-01-31' -CreatedAfter '2024-01-01'


Parameters

Mailbox
The Mailbox parameter specifies the mailbox to be accessed

Archive
The Archive parameter is a switch to search the archive mailbox (otherwise, the main mailbox is searched

ProcessSubfolders
The ProcessSubfolders parameter is a switch to enable searching the subfolders of any specified folder

IncludeFolderList
The IncludeFolderList parameter specifies the folder(s) to be searched (if not present, then the Inbox folder will be searched).  Any exclusions override this list.

ExcludeFolderList
The ExcludeFolderList parameter specifies the folder(s) to be excluded (these folders will not be searched).

MessageClass
The MessageClass parameter specifies the message class of the items being searched.

CreatedBefore
The CreatedBefore parameter specifies only messages created before this date will be searched.

CreatedAfter
The CreatedAfter parameter specifies only messages created after this date will be searched.

Subject
The Subject paramter specifies the subject string used by the search.

Sender
The Sender paramter specifies the sender email address used by the search.

Recipient
The Recipient paramter specifies the recipient email address used by the search (include Cc and Bcc).

MessageBody
The MessageBody parameter specifies the body string used by the search.

SearchDumpster
The SearchDumpster parameter is a switch to search the recoverable items.

MessageId
The MessageId parameter specified the MessageId used by the search.

ViewProperties
The ViewProperties parameter adds the given property(ies) to the list of those that will be retrieved for an item (must be supplied as hash table @{}).  By default, Id, Subject and Sender are retrieved.

DeleteContent
The DeleteContent parameter is a switch to delete the items found in the search results (moved to Deleted Items).

HardDelete
The HardDelete parameter is a swithch to hard-delete the items found in the search results (otherwise, they'll be moved to Deleted Items).

OAuthClientId
The OAuthClientId parameter is the Azure Application Id that this script uses to obtain the OAuth token.  Must be registered in Azure AD.

OAuthTenantId
The OAuthTenantId paramter is the tenant Id where the application is registered (Must be in the same tenant as mailbox being accessed).

OAuthRedirectUri
The OAuthRedirectUri parameter is the redirect Uri of the Azure registered application.

OAuthSecretKey
The OAuthSecretKey parameter is the the secret for the registered application.

OAuthCertificate
The OAuthCertificate parameter is the certificate for the registerd application. Certificate auth requires MSAL libraries to be available..

GlobalTokenStorage
The GlobalTokenStorage parameter is a switch when set, OAuth tokens will be stored in global variables for access in other scripts/console.  These global variable will be checked by later scripts using delegate auth to prevent additional log-in prompts.

OAuthDebug
The OAuthDebug parameter is used For debugging purposes.

DebugTokenRenewal
The DebugTokenRenewal parameter enables token debugging with a value greater than 0 (specify total number of token renewals to debug).

Impersonate
The Impersonate parameter enables impersonation to access the mailbox when set to True.

EWSManagedApiPath
The EWSManagedApiPath parameter specifies the path to managed API (if omitted, a search of standard paths is performed).

TraceFile
The TraceFile parameter specified the Trace file path - if specified, EWS tracing information is written to this file.

LogFile
The LogFile parameter specifies the Log file path - activity is logged to this file if specified.

VerboseLogFile
The VerboseLogFile parameter is a switch that enables verbose log file.  Verbose logging is written to the log whether -Verbose is enabled or not.

DebugLogFile
The DebugLogFile parameter is a switch that enables debug log file.  Debug logging is written to the log whether -Debug is enabled or not.

FastFileLogging
The FastFileLogging parameter is a switch that if selected, an optimised log file creator is used that should be signficantly faster (but may leave file lock applied if script is cancelled).

ResultsFile
The ResultsFile parameter specifies the results file path - items returned by the search results are saved into this file.
 
ThrottlingDelay
The ThrottlingDelay parameter specifies the throttling delay (time paused between sending EWS requests) - note that this will be increased automatically if throttling is detected.

BatchSize
The BatchSize parameter specifies the batch size (number of items batched into one EWS request) - this will be decreased if throttling is detected.



