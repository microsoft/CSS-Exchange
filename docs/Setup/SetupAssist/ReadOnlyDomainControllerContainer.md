---
title: Read Only Domain Controller - Domain Controllers OU
parent: SetupAssist.ps1
grand_parent: Setup
---

A Read Only Domain Controller appears to be in the container other than Domain Controller.
This will cause setup to fail if we attempt to domain prep that domain.
The path to the RODC must be CN=DCName,OU=Domain Controllers....
