# [Troubleshoot-ModernSearch.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1)

Download the latest release here: [https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Troubleshoot-ModernSearch.ps1)

This script is still in development. However, this should be able to quickly determine if an item is indexed or not and why it isn't indexed. Just provide the full message subject and user's email address and it will dump out the information needed to determine if the message is indexed or not.

## Example

```
.\Troubleshoot-ModernSearch.ps1 -UserEmail han@solo.com -ItemSubject "Test Message"
```