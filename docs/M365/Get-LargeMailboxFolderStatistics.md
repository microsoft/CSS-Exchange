# Get-LargeMailboxFolderStatistics

Download the latest release: [Get-LargeMailboxFolderStatistics.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Get-LargeMailboxFolderStatistics.ps1)


This script runs the Get-MailboxFolderStatistics cmdlet and works around the problem of cmdlet timeouts where there are a large number of folders in the mailbox. This is particularly useful with mailboxes with more than 10k folders, especially Archive mailboxes.
Although it can work with both Primary and Archive mailboxes.

By default the script will try and retrieve the folder statistics for a user's Archive mailbox. It will retrieve the folders in batches of 5000 and just retrieve the commonly required properties Name, FolderPath, ItemsInFolder, FolderSize, FolderAndSubfolderSize.


#### Syntax:

Example to get the mailbox folder statistics for an Archive mailbox.
```PowerShell
$folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com
```

Example to get the mailbox folder statistics for a Primary mailbox.
```PowerShell
$folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com -MailboxType Primary
```

Example to get the mailbox folder statistics for a Archive mailbox, in batches of 5000 and just the folder properties Name and FolderPath
```PowerShell
$folderStats = .\Get-LargeMailboxFolderStatistics.ps1 -Identity fred@contoso.com -MailboxType Archive -BatchSize 5000 -Properties @("Name", "FolderPath")
```



##### Further information <br>

The sweet spot seems to be retrieving folders in batches of about 5000 at a time. This prevents cmdlet timeouts but also achieves a good overall run time.

The script has been used successfully against archives mailboxes with up to 60K folders.

