---
title: Reboot Pending
parent: SetupAssist.ps1
grand_parent: Setup
---

It is best to reboot the server to address these issues. It may take some time after a reboot to have the keys automatically removed. However, if they don't remove automatically, follow these steps to address the issue for the keys that were provided to be a problem.

-  Open regedit to the desired location. Delete the key.
   - If unable to delete the key, follow these steps:
      - Right click on it
      - Open permissions
      - Click on Advanced
      - Change ownership to your account
      - Close Advanced window
      - Give your account Full Control in Permissions window
      - Delete the key

NOTE: With `Component Based Servicing\RebootPending` you need to do the same for `Component Based Servicing\PackagesPending` prior to `RebootPending`

NOTE: Follow the steps in this section carefully. Serious problems might occur if you modify the registry incorrectly. Before you modify it, [back up the registry for restoration](https://support.microsoft.com/en-us/topic/how-to-back-up-and-restore-the-registry-in-windows-855140ad-e318-2a13-2829-d428a2ab0692) in case problems occur.
