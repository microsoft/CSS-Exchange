---
title: Reboot Pending
parent: HealthChecker.ps1
grand_parent: Diagnostics
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
