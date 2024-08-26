# Update-PublicFolderPermissions

Download the latest release: [Update-PublicFolderPermissions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Update-PublicFolderPermissions.ps1)

This script can be used to set specific permissions on public folders in bulk or to propagate the full set of permissions from a parent folder to its entire subtree.

Environment|Support
-|-
Exchange Online|Supported
Exchange 2019|Not Supported

## Syntax

```powershell
Update-PublicFolderPermissions.ps1
    -IncludeFolders <String[]>
    -Users <String[]>
    -AccessRights <String[]>
    [-Recurse]
    [-ExcludeFolderEntryIds <String[]>]
    [-SkipCurrentAccessCheck]
    [-ProgressLogFile <String>]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]

Update-PublicFolderPermissions.ps1
    -IncludeFolders <String[]>
    -PropagateAll
    [-Recurse]
    [-ExcludeFolderEntryIds <String[]>]
    [-SkipCurrentAccessCheck]
    [-ProgressLogFile <String>]
    [-WhatIf]
    [-Confirm]
    [<CommonParameters>]
```

## Usage

```powershell
❯ .\Update-PublicFolderPermissions.ps1 -Users UserOne -AccessRights Owner -IncludeFolders "\FolderA" -Recurse -Confirm:$false
```

This syntax grants "UserOne" the Owner role on \FolderA and its entire subtree.

```powershell
❯ .\Update-PublicFolderPermissions.ps1 -Users UserOne, UserTwo -AccessRights Owner -IncludeFolders "\FolderA" -Recurse -Confirm:$false
```

This syntax grants both "UserOne" and "UserTwo" the Owner role on \FolderA and its entire subtree.

```powershell
❯ .\Update-PublicFolderPermissions.ps1 -PropagateAll -IncludeFolders "\FolderA" -Recurse -Confirm:$false
```

This syntax propagates all permissions from \FolderA to its entire subtree, including Default and Anonymous permissions.
Note that this option simply ensures that all the permission entries that exist on \FolderA also exist on all folders
underneath it. It does not remove permissions from child folders when those permissions do not exist on \FolderA.

## Notes about rights and roles

Historically, the FolderContact right and the FolderVisible right could be toggled on and off without affecting
the role. This behavior can still be seen in classic Outlook. If a user is given the Owner role, FolderContact can be
toggled on or off. Either way, the user still has the Owner role. Similarly, in classic Outlook, a user can be given
the None role with or without FolderVisible.

By contrast, the current EXO cmdlets assume that Owner always includes FolderContact, and None never includes
FolderVisible. Therefore, when propagating permissions with this script, None always means None _without_ FolderVisible,
and Owner always means Owner _with_ FolderContact.
