# [Troubleshoot-ModernSearch.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1)

This script is still in development. However, this should be able to quickly determine if an item is indexed or not and why it isn't indexed. Just provide the full message subject and the mailbox identity and it will dump out the information needed to determine if the message is indexed or not.

## Parameters

Parameter | Description
----------|------------
MailboxIdentity | Provide the identity of the mailbox that you wish to be looking at. If you are able to find it via `Get-Mailbox` it is able to be used here.
ItemSubject | Provide the message's subject name. Must be exact if `-MatchSubjectSubstring` isn't used. This includes if there is a trailing space at the end of the message subject.
MatchSubjectSubstring | Enable to perform a `like` search in the mailbox with the value that is passed with `-ItemSubject`.
FolderName | If you want to scope the search to a folder for better and faster results, include the name of the folder that the message is in.
DocumentId | If you already know the document ID number for the mailbox, provide this. This can not be use with `-ItemSubject` parameter.
QueryString | Include a string that you are using to try to find this item, we will run an instant query against it to see if we can find it.
IsArchive | Enable if you want to look at the archive mailbox.
IsPublicFolder | Enable if you want to look at a public folder mailbox.

## Examples

This is an example of how to run a basic query again a single item.

```
.\Troubleshoot-ModernSearch.ps1 -MailboxIdentity han@solo.com -ItemSubject "Test Message"
```

This is an example of how to run the script when you want to query multiple items with a similar subject name.

```
.\Troubleshoot-ModernSearch.ps1 -MailboxIdentity "Zelda01" -ItemSubject "Initial Indexing" -MatchSubjectSubstring
```

This is an example of how to run the script against an Archive Mailbox.

```
.\Troubleshoot-ModernSearch.ps1 -MailboxIdentity han@solo.com -ItemSubject "Test Message" -IsArchive
```

This is an example of how to run the script against a Public Folder Mailbox

```
.\Troubleshoot-ModernSearch.ps1 -MailboxIdentity PFMailbox2 -ItemSubject "My Item Test" -IsPublicFolder
```
