# Get-MissingMsUpdates
Uses the Windows Update Agent (WUA) to scan offline systems for security updates without connecting to Windows Update or Windows Server Update Services (WSUS). This script is a PowerShell variant of the code [Microsoft published](https://docs.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline) in 2020 and was designed to provide enhanced functionality.

## Parameters
### UpdateFile
The location of the stored wsusscn2.cab file. 
### OutFile
The location in which the ouput should be stored. The default output location is C:\Users\[USERNAME]\Desktop\MsScanReport.csv

## Script Execution Instructions
1.	Download an updated wsusscn2.cab file by [clicking here](http://go.microsoft.com/fwlink/p/?LinkID=74689).
2.	Transfer the updated wsusscn2.cab to the offline system using approved file transfer procedures.
3.	Point the `Get-MissingMsUpdates` PowerShell function to the wsusscn2.cab file using the `-UpdateFile` parameter.
4.	Wait for the script to finish executing.
5.	Review the .csv output file to determine which updates are missing.

## Example
```PowerShell
Get-MissingMsUpdates -UpdateFile C:\Temp\wsusscn2.cab
```
This command uses the `wsusscn2.cab` file that is stored in `C:\Temp` to query the system for missing updates. The output of the script is stored in the default location, `C:\Users\[USERNAME]\Desktop\MsScanReport.csv`.

## Example
```PowerShell
Get-MissingMsUpdates -UpdateFile C:\Temp\wsusscn2.cab -OutFile C:\Temp\MsScanReport.csv
```
This command uses the `wsusscn2.cab` file that is stored in `C:\Temp` to query the system for missing updates. The output of the script is stored in the location identified after the `-OutFile` parameter, `C:\Temp\MsScanReport.csv`.
