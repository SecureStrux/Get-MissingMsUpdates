# Get-MissingMsUpdates
Uses the Windows Update Agent (WUA) to scan offline systems for security updates without connecting to Windows Update or Windows Server Update Services (WSUS). This script is a PowerShell variant of the one [Microsoft published](https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline) in 2020 and was designed to provide enhanced functionality.

## Parameters
### UpdateFile
The location of the stored wsuscn2.cab file. 
### OutFile
The location in which the ouput should be stored. The default output location is C:\Users\[USERNAME]\Desktop\MsScanReport.csv

## Script Execution Instructions
1.	Download an updated [wsusscn2.cab](http://go.microsoft.com/fwlink/p/?LinkID=74689) file.
2.	Transfer the updated wsusscn2.cab to the offline system using approved file transfer procedures.
3.	Point the function to the wsuscn2.cab file using the `-UpdateFile` parameter.
4.	Wait for the script to finish executing.
5.	Review the .csv output file to determine which updates are missing.

## Example
