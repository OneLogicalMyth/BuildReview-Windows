# Setup
From a PowerShell window run the following:
```PowerShell
Import-Module "C:\path\to\root\folder\BuildReview.psd1"
New-BuildReviewCollector
```

You should now have a wsus cab file and a ps1 in the root of your %userprofile% folder. You need these both on the system to be audited, note the wsus cab file must be on the root of the C:\ drive; the script can be anywhere.

# Running the Script
You might find the script fails to run even when running as an administrative PowerShell window, issue the following command;
```PowerShell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```
*Process* is used here as it will ensure that after PowerShell is closed the client's security is restored.

To run simply launch PowerShell as an **administrator** then issue:
```PowerShell
.\BuildReview.ps1
```

In cases were a policy is enforcing the execution policy simply run this instead;
```PowerShell
iex [System.IO.File]::ReadAllText('c:\BuildReview.ps1')
```

# Exporting Results
The XML results for each host will be saved to your desktop, take the XMLs and save in 1 folder on your own machine. Now issue the following command;
```PowerShell
Export-AsHTML -InputFolder C:\Results\
```
A HTML file will be saved to *C:\Results* and any useful files collected will be stored in the sub directory **tool-output**.

# Coverage
It takes a lot of time to check each registry value is correct, I will get to the end eventually.

In the meantime ensure you read the raw XML results file generated as you will see blank results for some collections/groups/checks depending on the OS. Additionally, it is recommend each reported issue is verified to ensure accuracy.

In Scope:
* Windows 2012 R2
* Windows 2008 R2
* Windows 2016
* Windows 8.1
* Windows 10
* Windows 7

Out of Scope:
* Windows 2012
* Windows 2008
* Windows Vista
* Windows 8
* Windows XP
* Windows 2000 or older
