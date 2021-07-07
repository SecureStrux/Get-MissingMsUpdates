﻿Function Get-MissingMsUpdates {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)]
        $UpdateFile,
        [Parameter(Mandatory=$false)]
        $OutFile = "$env:USERPROFILE\Desktop\MsScanReport.csv"
    )

    #Perform switch operation on based on user privilege status.
    Switch(([security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
        
        #If the user is running as an administrator, write confirmation output to the shell.
        $TRUE {Write-Host "YOU ARE CURRENTLY RUNNING WITH THE REQUIRED PRIVILEGES!" -ForegroundColor Green}

        #If the user is not running as an administrator, output error to the shell.
        $FALSE {Write-Host "PLEASE RERUN WITH ADMINISTRATIVE PRIVILEGES!" -ForegroundColor Red}
    }

    #Create a session in which the caller can perform operations that involve updates.
    $updateSession = New-Object -ComObject Microsoft.Update.Session 

    #Add the registration of the update service with Windows Update Agent (WUA).
    $updateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager 

    #Register a scan package as a service with Windows Update Agent (WUA).
    $updateService = $updateServiceManager.AddScanPackageService("Offline Sync Service", $UpdateFile, 1) 

    #Create update searcher interface.
    $updateSearcher = $updateSession.CreateUpdateSearcher()

    #Identify server selection method as '3' (ssOthers), which configures the windows agent to 'search another server, to be specified by other means'.
    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-uamg/07e2bfa4-6795-4189-b007-cc50b476181a
    $updateSearcher.ServerSelection = 3

    #Convert the service ID to a string. This fixes an issue where Windows 10 truncates the service ID.
    $updateSearcher.ServiceID = [string]$updateService.ServiceID

    #Perform a synchronous search for updates. 'IsInstalled=0' finds updates that are not installed.
    $searchResult = $UpdateSearcher.Search("IsInstalled=0")

    #Return discovered updates.
    $requiredUpdates = $SearchResult.Updates 

    if($requiredUpdates.Count -eq 0){

        #If the required update count is 0, write that there are not applicable updates to the shell.
        Write-Host "There are no applicable updates." -ForegroundColor Green
    } else {

        #If the required update count is greater than 0, loop through each update to create a custom powershell object.
        $requiredUpdates | ForEach-Object {
            [PSCustomObject]@{
                Title = $Update.Title
                Severity = $Update.MsrcSeverity
                Description = $Update.Description
                URL = $Update.SupportUrl
            }
        } | Export-Csv $OutFile -NoTypeInformation
    }

    #Determine if there is a ScanFile directory.
    if (Test-Path C:\Windows\SoftwareDistribution\ScanFile) {

        #If the ScanFile directory exists, remove its contents.
        Remove-Item C:\Windows\SoftwareDistribution\ScanFile\* -Recurse
    }
}